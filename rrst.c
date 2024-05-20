// SPDX-License-Identifier: GPL-2.0+

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/syscall.h> 
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include <libudev.h>

#include "rrst.h"
#include "ttypersist.h"
#include "control.h"
#include "config.h"

#define SOCK_PATH "/run/user/%d/rrst-%d.sock"
#define SERVER 0
#define CLIENT 1

void usage() {
	fprintf(stderr, "Usage: rrst [-d [-s SOCKET] -c CONFIG_PATH]|[COMMAND]\n");
	fprintf(stderr, "       rrst (reset|bootloader|up|pwr|pty|baud)\n");
	fprintf(stderr, "\t-d             : run daemon\n");
	fprintf(stderr, "\t-c             : path to device config\n");
	fprintf(stderr, "\treset          : reset the board\n");
	fprintf(stderr, "\tbootloader     : enter bootloader mode\n");
	fprintf(stderr, "\tup             : press the up button (serial RTS pin)\n");
	fprintf(stderr, "\tpwr            : press the power button (serial DTR pin)\n");
	fprintf(stderr, "\trelease        : release all buttons\n");
	fprintf(stderr, "\tpty            : get the pty path for your serial console\n");
	fprintf(stderr, "\tbaud           : toggle the serial baud manually (115200/3000000)\n");
	fprintf(stderr, "\ttest <pass> <fail> [timeout] : wait until either pass or fail string is found in serial output\n");
	fprintf(stderr, "                                 exit with 0 on success, 1 on timeout, 2 on fail\n");
	fprintf(stderr, "\tuart <msg> <prompt>          : send <msg> to the uart and return output up to <prompt>\n");
}

static const char *action_names[] = {
	[INVALID] = "invalid",
	[RESET] = "reset",
	[BOOTLOADER] = "bootloader",
	[UP] = "up",
	[PWR] = "pwr",
	[RELEASE] = "release",
	[PTY] = "pty",
	[BAUD] = "baud",
	[TEST] = "test",
	[UART] = "uart",
};

struct rrst_test_state {
	char pass[128];
	union {
		char fail[128];
		struct {
			char msg[128];
			char output[32168];
		};
	};
	int fd;
	bool in_progress;
	int send_msg : 8; /* for "UART" action, if msg should be sent to the device
	* step 1: send the msg
	* step 2: wait for echo
	* step 3: echo received
	*/
	bool uart; /* true if UART action */
	struct sockaddr_un addr_client;
};

struct rrst_action_state {
	pthread_t thread;
	pthread_cond_t newaction;
	enum actions action;
	pthread_mutex_t mutex; /* Locked while action in progress */
	struct sockaddr_un addr_client;
	bool in_progress;
	int fd;
	char ptyname[64];
};

static struct rrst_test_state test_state;

#define NOTIFY_QUIT 0xff
#define NOTIFY_PTY_DISCONNECT 0x01
/* A message from the server to the PTY is pending */
#define NOTIFY_USER_MSG 0x02

int ttyfd;
bool quit;
static int notifyfd, ptyfd;
static char socket_path[PATH_MAX];
static speed_t current_baud;
static struct rrst_config config;
static struct rrst_control control;

#define CURRENT_BAUD_STR (current_baud == B115200 ? "115200" : "3000000")

int die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int _set_baud(int fd, speed_t speed, bool make_raw)
{
	struct termios termios;
	if (tp_ioctl(fd, TCGETS, &termios))
		die("tcgetattr()");

	cfsetispeed(&termios, speed);
	cfsetospeed(&termios, speed);

	if (make_raw)
		cfmakeraw(&termios);

	if (tp_ioctl(fd, TCSETS, &termios))
		die("tcsetattr()");

	current_baud = speed;
	if (fd == ttyfd)
		printf("tty: new baud %s\n", CURRENT_BAUD_STR);

	return 0;
}

static int set_baud(speed_t speed, bool make_raw)
{
	return _set_baud(ttyfd, speed, make_raw)
	    || _set_baud(ptyfd, speed, make_raw);
}

#define FASTBOOT_PATH "/dev/android_fastboot"

static bool device_is_fastboot(struct udev_device *dev) {
	struct udev_list_entry *devlinks, *link;
	devlinks = udev_device_get_devlinks_list_entry(dev);

	udev_list_entry_foreach(link, devlinks) {
		const char *name = udev_list_entry_get_name(link);
		if (strncmp(name, FASTBOOT_PATH, strlen(FASTBOOT_PATH)) == 0)
			return true;
	}

	return false;
}

// Hold power and volume up for 12.5 seconds
// Keep holding until fastboot device detected (:
static void board_bootloader(struct udev_monitor *mon, struct rrst_msg *msg) {
	int fd;
	control.start_bootloader(msg);
	set_baud(config.baud_bootloader, false);
	udev_monitor_enable_receiving(mon);
	fd = udev_monitor_get_fd(mon);
	/* Wait until fastboot device detected, or timeout */
	struct timeval tv = { .tv_sec = 300, .tv_usec = 0 };
	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	while (true) {
		int ret = select(fd + 1, &fds, NULL, NULL, &tv);
		if (ret == -1) {
			fprintf(stderr, "select() failed: %s\n", strerror(errno));
			break;
		} else if (ret == 0) {
			fprintf(stderr, "Timeout waiting for fastboot device\n");
			break;
		}

		struct udev_device *dev = udev_monitor_receive_device(mon);
		if (dev) {
			const char *action = udev_device_get_action(dev);
			if (action && strcmp(action, "bind") == 0) {
				if (device_is_fastboot(dev)) {
					printf("Action: %s\n", action);
					break;
				}
			}
			udev_device_unref(dev);
		}
	}

	control.release(msg);
}

static void sigterm_handler(int signum) {
	quit = true;
	control.release(NULL);
	if (control.exit)
		control.exit();
	int x = NOTIFY_QUIT;
	send(notifyfd, &x, sizeof(x), 0);
	unlink(socket_path);
	printf("\n");
}

/* Called on every connect including the first one */
static void reconnect_handler(void *priv, int fd) {
	control.on_connect(fd > 0);
}

static enum actions parse_action(const char *action_str)
{
	for (int i = 1; i < sizeof(action_names) / sizeof(action_names[0]); i++) {
		if (strcmp(action_names[i], action_str) == 0) {
			return i;
		}
	}

	return INVALID;
}

struct rrst_sock {
	int fd;
	struct sockaddr_un addr;
	struct sockaddr_un client_addr;
};

static int init_socket(int *fd, struct sockaddr_un *addr)
{
	*fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (*fd == -1) {
		fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, sizeof(addr->sun_path), SOCK_PATH, getuid(), SERVER);

	return 0;
}

static int bind_socket(int fd, struct sockaddr_un *addr)
{
again:
	if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) == -1) {
		if (errno == EADDRINUSE) {
			fprintf(stderr, "Socket file '%s' already exists, is another instance running?\n",
				addr->sun_path);
			unlink(addr->sun_path);
			goto again;
		}
		else
			fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static void *server_action_thread(void *data) {
	struct rrst_action_state *state = data;
	struct rrst_msg msg;
	struct udev *udev;
	struct udev_monitor *monitor;
	socklen_t addrlen = sizeof(state->addr_client);
	unsigned long notify = 0;

	/* udev monitor to detect when device enters fastboot mode */
	udev = udev_new();
	if (!udev) {
		fprintf(stderr, "Failed to create udev context\n");
		quit = true;
		notify = 0xff;
		write(notifyfd, &notify, sizeof(notify));
		return NULL;
	}

	monitor = udev_monitor_new_from_netlink(udev, "udev");
	udev_monitor_filter_add_match_subsystem_devtype(monitor, "usb", "usb_device");

	while (true) {
		pthread_mutex_lock(&state->mutex);
		pthread_cond_wait(&state->newaction, &state->mutex);

		switch (state->action) {
		case INVALID:
			fprintf(stderr, "Invalid action!\n");
			msg.type = MSG_ERR;
			strncpy(msg.info, "ERROR: Invalid action", sizeof(msg.info) - 1);
			break;
		case RESET:
			control.reset(&msg);
			break;
		case BOOTLOADER:
			board_bootloader(monitor, &msg);
			break;
		case UP:
			control.up(&msg);
			break;
		case PWR:
			control.pwr(&msg);
			break;
		case RELEASE:
			control.release(&msg);
			break;
		case BAUD:
			if (set_baud(current_baud == config.baud_linux ? config.baud_bootloader : config.baud_linux, false)) {
				msg.type = MSG_ERR;
				snprintf(msg.info, sizeof(msg.info) - 1, "ERROR: failed to set baud: %s", strerror(errno));
			} else {
				msg.type = MSG_INFO;
				snprintf(msg.info, sizeof(msg.info) - 1, "set baud %s", CURRENT_BAUD_STR);
			}
			break;
		default:
			fprintf(stderr, "Fell through!!! %d\n", state->action);
			break;
		}

		// We don't care if this fails, it just means the client is gone
		sendto(state->fd, &msg, sizeof(msg), 0, (struct sockaddr*)&state->addr_client, addrlen);
		pthread_mutex_unlock(&state->mutex);
	}

	udev_monitor_unref(monitor);
	udev_unref(udev);
	return NULL;
}

static int handle_action(const char *port, struct rrst_action_state *state)
{
	int len, ret;
	struct rrst_msg msg;
	enum actions action;
	socklen_t addrlen = sizeof(state->addr_client);

	len = recvfrom(state->fd, &msg, sizeof(msg), 0, (struct sockaddr*)&state->addr_client, &addrlen);
	if (len < 0) {
		fprintf(stderr, "Failed to receive message: %s\n", strerror(errno));
		return -1;
	}

	switch (msg.type) {
	case MSG_ACTION:
		action = msg.action;
		if (action == TEST || action == UART) {
			test_state.fd = state->fd;
			strncpy(test_state.pass, msg.info, sizeof(test_state.pass) - 1);
			if (action == TEST) {
				strncpy(test_state.fail, msg.info2, sizeof(test_state.fail) - 1);
			} else {
				strncpy(test_state.msg, msg.info2, sizeof(test_state.msg) - 1);
				test_state.send_msg = 1;
				test_state.uart = true;
			}
			memcpy(&test_state.addr_client, &state->addr_client, sizeof(state->addr_client));
			test_state.in_progress = true;
		}
		memset(&msg, 0, sizeof(msg));
		break;
	default:
		fprintf(stderr, "Invalid message type: %d\n", msg.type);
		return -1;
	}

	printf("Handling action: '%s'\n", action_names[action]);

	if (action == UART)
		return 0;

	if (action == PTY || action == TEST) {
		msg.type = MSG_INFO;
		strncpy(msg.info, action == PTY ? state->ptyname : "ACK!", sizeof(msg.info) - 1);
		if (sendto(state->fd, &msg, sizeof(msg), 0, (struct sockaddr*)&state->addr_client, addrlen) < 0)
			fprintf(stderr, "Failed to send reply: %s\n", strerror(errno));
		return 0;
	}

	if ((ret = pthread_mutex_trylock(&state->mutex)) == EBUSY) {
		msg.type = MSG_ERR;
		strncpy(msg.info, "ERROR: Action already in progress", sizeof(msg.info) - 1);
		if (sendto(state->fd, &msg, sizeof(msg), 0, (struct sockaddr*)&state->addr_client, addrlen) < 0)
			fprintf(stderr, "Failed to send reply: %s\n", strerror(errno));
		return 0;
	}

	if (ret && ret != EBUSY) {
		fprintf(stderr, "Failed to lock mutex: %s\n", strerror(ret));
		quit = true;
		return -1;
	}

	state->action = action;

	pthread_cond_broadcast(&state->newaction);
	pthread_mutex_unlock(&state->mutex);

	return 0;
}

static void test_pass(const char *line)
{
	struct rrst_msg msg = { 0 };
	int ret;

	msg.type = MSG_INFO;

	/* For UART action when we get the pass prompt send a null msg */
	if (!test_state.uart) {
		printf("Test passed!\n");
		strncpy(msg.info, "PASS!", sizeof(msg.info) - 1);
	}
	ret = sendto(test_state.fd, &msg, sizeof(msg), 0, (struct sockaddr*)&test_state.addr_client, sizeof(test_state.addr_client));
	if (ret < 0)
		fprintf(stderr, "Failed to send reply: %s\n", strerror(errno));
	test_state.in_progress = false;
}

static void handle_test_detect(const char *line)
{
	struct rrst_msg msg;
	int ret;

	if (!test_state.in_progress)
		return;
	
	/* Send the lines back */
	if (test_state.uart) {
		msg.type = MSG_INFO;
		strncpy(msg.info, test_state.output, sizeof(msg.info) - 1);
		ret = sendto(test_state.fd, &msg, sizeof(msg), 0, (struct sockaddr*)&test_state.addr_client, sizeof(test_state.addr_client));
		if (ret < 0) {
			fprintf(stderr, "Failed to send reply: %s\n", strerror(errno));
			/* Bail out */
			test_state.in_progress = false;
		}
		return;
	}

	if (!test_state.uart && strstr(line, test_state.fail)) {
		printf("Test failed!\n");
		msg.type = MSG_ERR;
		strncpy(msg.info, "FAIL!", sizeof(msg.info) - 1);
		ret = sendto(test_state.fd, &msg, sizeof(msg), 0, (struct sockaddr*)&test_state.addr_client, sizeof(test_state.addr_client));
		if (ret < 0)
			fprintf(stderr, "Failed to send reply: %s\n", strerror(errno));
		test_state.in_progress = false;
	}

	return;
}

#define MSG_QUEUE_SIZE 64

static struct {
	pthread_mutex_t mutex;
	const char *msgs[MSG_QUEUE_SIZE];
	int head, tail;
} user_messages = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};

void print_serial(const char *fmt, ...)
{
	va_list args;
	char buf[4096];
	int len;

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len < 0 || len >= sizeof(buf)) {
		fprintf(stderr, "Failed to format message\n");
		return;
	}

	pthread_mutex_lock(&user_messages.mutex);
	user_messages.msgs[user_messages.head] = strdup(buf);
	user_messages.head = (user_messages.head + 1) % MSG_QUEUE_SIZE;
	if (user_messages.head == user_messages.tail)
		user_messages.tail = (user_messages.tail + 1) % MSG_QUEUE_SIZE;
	pthread_mutex_unlock(&user_messages.mutex);

	eventfd_write(notifyfd, NOTIFY_USER_MSG);
}

#define MSG_LINE_START "\033[34m"
#define MSG_LINE_END "\033[0m\r\n"

/* Print pending user messages (info stuff) opportunistically 
 * unless block is true, in which case wait for the mutex.
 */
static int tty_print_user_messages(bool block)
{
	int ret = 0;
	const char *buf;

	if (!user_messages.msgs[user_messages.tail])
		return 0;

	printf("Pending msg, block %d\n", block);

	if (block)
		pthread_mutex_lock(&user_messages.mutex);
	else if (pthread_mutex_trylock(&user_messages.mutex))
		return 0;

	while (user_messages.tail != user_messages.head) {
		buf = user_messages.msgs[user_messages.tail];
		if (!block)
			write(ptyfd, "\r\n", 2);
		write(ptyfd, MSG_LINE_START, strlen(MSG_LINE_START));
		write(ptyfd, buf, strlen(buf));
		write(ptyfd, MSG_LINE_END, strlen(MSG_LINE_END));
		free((void*)buf);
		user_messages.msgs[user_messages.tail] = NULL;
		user_messages.tail = (user_messages.tail + 1) % MSG_QUEUE_SIZE;
		ret++;
	}

	pthread_mutex_unlock(&user_messages.mutex);

	return ret;
}

static int handle_tty(int fd)
{
	static char tty_line[4096];
	static int tty_line_len = 0;
	static char *prompt = NULL;
	unsigned char buf;
	int ret, wfd;

	

	ret = read(fd, &buf, sizeof(buf));
	if (ret < 0) {
		/* Either the serial port or the PTY disconnected
		 * we don't actually care about either.
		 */
		if (errno == EIO)
			return 0;
		fprintf(stderr, "Failed to read from tty: %s\n", strerror(errno));
		return -1;
	}

	if (fd == ttyfd) {
		tty_line[tty_line_len++] = buf;
		if (test_state.in_progress) {
			if (!prompt)
				prompt = test_state.pass;

			if (*prompt == buf) {
				prompt++;
				if (*prompt == '\0') {
					prompt = NULL;
					test_pass(tty_line);
				}
			}
		}

		if (buf == '\n') {
			if (current_baud == config.baud_bootloader && config.linux_detect && strstr(tty_line, config.linux_detect)) {
				printf("Linux transition detected\n");
				set_baud(config.baud_linux, false);
			}
			if (test_state.send_msg == 2) {
				if (strstr(tty_line, test_state.msg))
					test_state.send_msg = 3;
			} else if (test_state.in_progress) {
				if (test_state.uart) {
					memset(test_state.output, 0, sizeof(test_state.output));
					strncpy(test_state.output, tty_line, sizeof(test_state.output) - 1);
				}
				handle_test_detect(tty_line);
			}
			memset(tty_line, 0, sizeof(tty_line));
			tty_line_len = 0;

			// Print pending user messages if the mutex isn't locked and
			// we're in the ttyfd context
			tty_print_user_messages(false);
		}

		if (tty_line_len >= sizeof(tty_line)) {
			memset(tty_line, 0, sizeof(tty_line));
			tty_line_len = 0;
		}
	}

	//printf("tty: %c\n", buf);

	wfd = ttyfd == fd ? ptyfd : ttyfd;
	ret = write(wfd, &buf, sizeof(buf));

	return 0;
}

static int server_mainloop(const char *config_path)
{
	struct sigaction sigterm_action = {
		.sa_handler = sigterm_handler,
		.sa_flags = 0,
	};
	struct rrst_action_state state = {
		.action = INVALID,
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.newaction = PTHREAD_COND_INITIALIZER,
	};
	struct sockaddr_un addr;
	int ret = 0;

	memset(&addr, 0, sizeof(addr));
	/* For journalctl */
	setvbuf(stdout, NULL, _IONBF, 0);

	if (rrst_load_config(config_path, &config)) {
		fprintf(stderr, "Failed to load config file: %s\n", config_path);
		return 1;
	}

	switch (config.control_method) {
		case RRST_CONTROL_RTS_DTR:
			control = rts_dtr_control;
			break;
		case RRST_CONTROL_QCOM_DBG:
			control = qcom_dbg_control;
			break;
		default:
			fprintf(stderr, "Invalid control method: %d\n", config.control_method);
			return 1;
	}

	if (control.init && control.init(&config)) {
		fprintf(stderr, "Failed to initialize control method\n");
		return 1;
	}

	printf("Using port: %s\n", config.port);

	ttyfd = tp_open(config.port, reconnect_handler, (void*)config.port, 0);
	if(ttyfd == -1) {
		fprintf(stderr, "Error! opening %s\n", config.port);
		return errno;
	}

	ret = tp_flock(ttyfd, LOCK_EX);
	if (ret < 0) {
		if (errno == EWOULDBLOCK) {
			fprintf(stderr, "Error: Can't lock %s, another process is using it\n", config.port);
			//return errno;
		}

		fprintf(stderr, "Error: flock() failed: %s\n", strerror(errno));
	}

	if (init_socket(&state.fd, &addr) < 0)
		return 1;

	strncpy(socket_path, addr.sun_path, sizeof(socket_path) - 1);

	if (bind_socket(state.fd, &addr) < 0) {
		close(state.fd);
		if (errno != EADDRINUSE)
			unlink(socket_path);
		return 1;
	}

	sigemptyset(&sigterm_action.sa_mask);
	sigaction(SIGTERM, &sigterm_action, NULL);
	sigaction(SIGINT, &sigterm_action, NULL);

	notifyfd = eventfd(0, 0);
	if (notifyfd < 0) {
		fprintf(stderr, "Failed to create eventfd: %s\n", strerror(errno));
		close(state.fd);
		return 1;
	}

	ptyfd = open("/dev/ptmx", O_RDWR);
	if (ptyfd < 0) {
		fprintf(stderr, "Failed to open /dev/ptmx: %s\n", strerror(errno));
		close(state.fd);
		close(notifyfd);
		unlink(socket_path);
		return 1;
	}

	if (grantpt(ptyfd) < 0) {
		fprintf(stderr, "Failed to grantpt: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	if (unlockpt(ptyfd) < 0) {
		fprintf(stderr, "Failed to unlockpt: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	if (ptsname_r(ptyfd, state.ptyname, sizeof(state.ptyname)) < 0) {
		fprintf(stderr, "Failed to get pty name: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	printf("Using pty: %s\n", state.ptyname);

	printf("Setting baud to bootloader rate: %d\n", config.baud_bootloader);
	set_baud(config.baud_bootloader, true);

	if (pthread_create(&state.thread, NULL, server_action_thread, &state)) {
		fprintf(stderr, "Failed to create thread: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

#define N_FDS 4
	bool user_msg_pending = false;
	while (true) {
		struct pollfd fds[N_FDS];
		fds[0].fd = state.fd;
		fds[1].fd = notifyfd;
		fds[2].fd = ttyfd;
		fds[3].fd = ptyfd;
		for (int i = 0; i < N_FDS; i++)
			fds[i].events = POLLIN;

		if ((ret = poll(fds, N_FDS, 50)) <= 0) {
			if (ret == 0) { // TIMEDOUT
				tty_print_user_messages(true);
				user_msg_pending = false;
				if (test_state.send_msg == 1) {
					write(ttyfd, test_state.msg, strlen(test_state.msg));
					write(ttyfd, "\n", 1);
					// write(ptyfd, test_state.msg, strlen(test_state.msg));
					// write(ptyfd, "\r\n", 2);
					test_state.send_msg = 2;
				}
				continue;
			}
			fprintf(stderr, "Failed to select: %s\n", strerror(errno));
			ret = 1;
			goto out;
		}

		/* state.fd */
		if (fds[0].revents & POLLIN) {
			if (handle_action(config.port, &state) < 0) {
				ret = 1;
				goto out;
			}
		}

		/* notifyfd */
		if (fds[1].revents & POLLIN) {
			printf("notifyfd\n");
			uint64_t notify;
			if (read(notifyfd, &notify, sizeof(notify)) < 0) {
				fprintf(stderr, "Failed to read from eventfd: %s\n", strerror(errno));
				ret = 1;
				goto out;
			}

			switch (notify) {
			case NOTIFY_QUIT:
				quit = true;
				break;
			case NOTIFY_PTY_DISCONNECT:
				printf("%s: %s\n", config.port, "Disconnected");
				break;
			case NOTIFY_USER_MSG:
				printf("User message\n");
				if (user_msg_pending)
					tty_print_user_messages(true);
				else
					user_msg_pending = true;
				break;
			default:
				fprintf(stderr, "Unknown notification: %lu\n", notify);
				ret = 1;
				goto out;
			}
		}

		/* ttyfd */
		if (fds[2].revents & POLLIN) {
			//printf("ttyfd\n");
			if (handle_tty(ttyfd) < 0) {
				ret = 1;
				goto out;
			}
		}

		/* ptyfd */
		if (fds[3].revents & POLLIN) {
			//printf("ptyfd\n");
			if (handle_tty(ptyfd) < 0) {
				ret = 1;
				goto out;
			}
		}

		if (quit)
			break;

	}

out:
	pthread_kill(state.thread, SIGKILL);
	close(ptyfd);
	close(ttyfd);
	close(state.fd);
	close(notifyfd);
	unlink(socket_path);
	return ret;
}

static void client_sigterm_handler(int sig)
{
	unlink(socket_path);
	quit = true;
	close(notifyfd);
}

static int do_action(enum actions action)
{
	struct rrst_msg msg;
	struct sockaddr_un addr;
	struct sockaddr_un addr_client;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	int len = 0;
	struct sigaction sigterm_action = {
		.sa_handler = client_sigterm_handler,
		.sa_flags = 0,
	};

	memset(&addr, 0, sizeof(addr));
	memset(&addr_client, 0, sizeof(addr_client));

	//sigemptyset(&sigterm_action.sa_mask);
	sigaction(SIGTERM, &sigterm_action, NULL);
	sigaction(SIGINT, &sigterm_action, NULL);

	if (init_socket(&notifyfd, &addr) < 0)
		return 1;

	addr_client.sun_family = AF_UNIX;
	snprintf(addr_client.sun_path, sizeof(addr_client.sun_path), SOCK_PATH, getuid(), getpid());
	strncpy(socket_path, addr_client.sun_path, sizeof(socket_path) - 1);

	//fprintf(stderr, "Using socket: %s\n", socket_path);

	if (bind_socket(notifyfd, &addr_client) < 0) {
		close(notifyfd);
		if (errno != EADDRINUSE)
			unlink(socket_path);
		return 1;
	}

	if (connect(notifyfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "RRST: Failed to connect to socket: %s\n", strerror(errno));
		goto out;
	}

	if (setsockopt(notifyfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "RRST: Failed configure socket timeout: %s\n", strerror(errno));
		goto out;
	}

	memset(&msg, 0, sizeof(msg));
	msg.type = MSG_ACTION;
	msg.action = action;

	if (action == TEST) {
		strncpy(msg.info, test_state.pass, sizeof(msg.info) - 1);
		strncpy(msg.info2, test_state.fail, sizeof(msg.info2) - 1);
	} else if (action == UART) {
		strncpy(msg.info, test_state.fail, sizeof(msg.info) - 1);
		strncpy(msg.info2, test_state.pass, sizeof(msg.info2) - 1);
	}

	if (send(notifyfd, &msg, sizeof(msg), 0) == -1) {
		fprintf(stderr, "RRST: Failed to send message, is rrst running? %s\n", strerror(errno));
		goto out;
	}

	bool got_test_ack = false;

wait_test_result:
	memset(&msg, 0, sizeof(msg));
	struct pollfd fds[1];
	fds[0].fd = notifyfd;
	fds[0].events = POLLIN;
	int timeout = action == TEST ? -1 : 15000;

	if (poll(fds, 1, timeout) < 0) {
		fprintf(stderr, "RRST: Failed to poll for response %s\n", strerror(errno));
		goto out;
	}
	len = recv(notifyfd, &msg, sizeof(msg), 0);
	if (len == -1) {
		fprintf(stderr, "RRST: Failed to receive message, is rrst running? %s\n", strerror(errno));
		goto out;
	}

	switch (msg.type) {
	case MSG_ACK:
		printf("%s done!\n", action_names[action]);
		break;
	case MSG_ERR:
		printf("%s\n", msg.info);
		len = 0;
		break;
	case MSG_INFO:
		printf("%s", msg.info);
		if (strlen(msg.info) > 0) {
			/* Loop until we get a null msg */
			if (action == UART) {
				goto wait_test_result;
			}
		} else if (action == UART) {
			len = 1;
		}

		if (action == TEST) {
			if (!got_test_ack) {
				got_test_ack = true;
				goto wait_test_result;
			} else {
				printf("\n");
			}
			len = 1;
		}
		break;
	default:
		printf("RRST: Unexpected response type: %d\n", msg.type);
		break;
	}

out:
	close(notifyfd);
	unlink(socket_path);
	return len > 0 ? 0 : 1;
}

int main(int argc, char *argv[])
{
	enum actions action = INVALID;

	int opt;
	bool daemon = false;
	const char *config_path = NULL;
	while ((opt = getopt(argc, argv, "dc:h")) != -1) {
		switch (opt) {
		case 'd':
			daemon = true;
			break;
		case 'c':
			config_path = optarg;
			break;
		case 'h':
			usage();
			return 127;
		default:
			usage();
			return 127;
		}
	}

	quit = false;

	if (daemon) {
		if (!config_path) {
			fprintf(stderr, "Must specify a config file for the daemon.\n");
			return 1;
		}

		if (optind < argc) {
			fprintf(stderr, "Can't specify an action and a config file.\n");
			return 1;
		}

		return server_mainloop(config_path);
	}

	// Invoke an action (client)
	if (optind < argc) {
		action = parse_action(argv[optind++]);
	}
	
	if (action == INVALID) {
		fprintf(stderr, "No arguments specified!\n");
		usage();
		return 1;
	}

	if (action == TEST || action == UART) {
		if (argc - optind < 2) {
			fprintf(stderr, "Must specify a pass and fail string!\n");
			usage();
			return 1;
		}

		strncpy(test_state.pass, argv[optind++], sizeof(test_state.pass) - 1);
		strncpy(test_state.fail, argv[optind++], sizeof(test_state.fail) - 1);
	}

	return do_action(action);
}
