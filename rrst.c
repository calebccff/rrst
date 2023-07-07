/* From https://github.com/freedomlives/RTS-DTR-Pin-Control-Linux/blob/master/serial_rts_dtr.c */

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
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include <libudev.h>

#include "ttypersist.h"

#define SOCK_PATH "/run/user/%d/rrst-%d.sock"
#define SERVER 0
#define CLIENT 1
#define MS 1000

void usage() {
	fprintf(stderr, "Usage: rrst (-s /dev/ttyUSB0|reset|bootloader|up|pwr|pty|baud)\n");
	fprintf(stderr, "\t-s             : run daemon on a given port\n");
	fprintf(stderr, "\treset          : reset the board\n");
	fprintf(stderr, "\tbootloader     : enter bootloader mode\n");
	fprintf(stderr, "\tup             : press the up button (serial RTS pin)\n");
	fprintf(stderr, "\tpwr            : press the power button (serial DTR pin)\n");
	fprintf(stderr, "\trelease        : release all buttons\n");
	fprintf(stderr, "\tpty            : get the pty path for your serial console\n");
	fprintf(stderr, "\tbaud           : toggle the serial baud manually (115200/3000000)\n");
}

enum actions {
	INVALID = 0,
	RESET,
	BOOTLOADER,
	UP,
	PWR,
	RELEASE,
	QUIT,
	PTY,
	BAUD,
};

static const char *action_names[] = {
	[INVALID] = "invalid",
	[RESET] = "reset",
	[BOOTLOADER] = "bootloader",
	[UP] = "up",
	[PWR] = "pwr",
	[RELEASE] = "release",
	[PTY] = "pty",
	[QUIT] = "quit",
	[BAUD] = "baud",
};

enum rrst_msg_type {
	/* Client -> Server */
	MSG_ACTION = 1,

	/* Server -> Client */
	MSG_ACK,
	MSG_INFO,
	MSG_ERR,
};

struct rrst_msg {
	enum rrst_msg_type type;
	bool block; /* Don't send ACK until sequence is complete */
	union {
		enum actions action;
		char info[64];
	};
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

#define NOTIFY_QUIT 0xff
#define NOTIFY_PTY_DISCONNECT 0x01

static int ttyfd, notifyfd, ptyfd, rts = TIOCM_RTS, dtr = TIOCM_DTR;
static char socket_path[PATH_MAX];
static bool quit = false, serial_attached = false;
static speed_t current_baud;

#define CURRENT_BAUD_STR (current_baud == B115200 ? "115200" : "3000000")

#define btn_pwr (dtr) // set to press
#define btn_up (rts) // clear to press

#define btn_name(btn) (btn == btn_pwr ? "power" : "up")

int die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void press_btn(int btn) {
	if (!serial_attached) return;
	if (!quit) printf("%s: press\n", btn_name(btn));
	tp_ioctl(ttyfd, TIOCMBIS, &btn);
}

void release_btn(int btn) {
	if (!serial_attached) return;
	if (!quit) printf("%s: release\n", btn_name(btn));
	tp_ioctl(ttyfd, TIOCMBIC, &btn);
}

#define press_pwr() press_btn(btn_pwr)
#define press_up() press_btn(btn_up)
#define release_pwr() release_btn(btn_pwr)
#define release_up() release_btn(btn_up)

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

int set_baud(speed_t speed, bool make_raw)
{
	return _set_baud(ttyfd, speed, make_raw)
	    || _set_baud(ptyfd, speed, make_raw);
}

void start_reset_set_baud()
{
	press_pwr();
	press_up();
	usleep(10000 * MS);
	set_baud(B115200, false);
	set_baud(B115200, false);
	usleep(2500 * MS);
}

// Hold power and volume up for 10.5 seconds
// release volume up and hold power for 1.5 seconds
void board_reset() {
	start_reset_set_baud();
	release_up();
	release_pwr();
}

#define FASTBOOT_PATH "/dev/android_fastboot"

bool device_is_fastboot(struct udev_device *dev) {
	struct udev_list_entry *devlinks, *link;
	devlinks = udev_device_get_devlinks_list_entry(dev);

	udev_list_entry_foreach(link, devlinks) {
		const char *name = udev_list_entry_get_name(link);
		//printf("link: %s\n", name);
		if (strncmp(name, FASTBOOT_PATH, strlen(FASTBOOT_PATH)) == 0)
			return true;
	}

	return false;
}

// Hold power and volume up for 12.5 seconds
// Keep holding until fastboot device detected (:
void board_bootloader(struct udev_monitor *mon) {
	int fd;
	start_reset_set_baud();
	udev_monitor_enable_receiving(mon);
	fd = udev_monitor_get_fd(mon);
	/* Wait until fastboot device detected, or timeout */
	struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
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
				if (device_is_fastboot(dev))
					break;
			}
			udev_device_unref(dev);
		}
	}
	release_pwr();
	release_up();
}

void board_up() {
	press_up();
	usleep(50 * MS);
	release_up();
}

void board_pwr() {
	press_pwr();
	usleep(50 * MS);
	release_pwr();
}

void get_pty(int *fd)
{
	(*fd) = open("/dev/ptmx", O_RDWR);
	if (grantpt((*fd)))
		die("grantpt");

	if (unlockpt((*fd)))
		die("unlockpt");
}

void sigterm_handler(int signum) {
	quit = true;
	release_pwr();
	release_up();
	int x = NOTIFY_QUIT;
	send(notifyfd, &x, sizeof(x), 0);
	unlink(socket_path);
	printf("\n");
}

/* Called on every connect including the first one */
void reconnect_handler(void *priv, int fd) {
	serial_attached = fd > 0;
	if (serial_attached) {
		printf("Reconnected to %s\n", (char *)priv);
		release_pwr();
		release_up();
	}
}

enum actions parse_action(const char *action_str)
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

int init_socket(int *fd, struct sockaddr_un *addr)
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

int bind_socket(int fd, struct sockaddr_un *addr)
{
	if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) == -1) {
		if (errno == EADDRINUSE)
			fprintf(stderr, "Socket file '%s' already exists, is another instance running?\n",
				addr->sun_path);
		else
			fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int connect_socket(int fd, struct sockaddr_un *addr)
{
	if (connect(fd, (struct sockaddr *)addr, sizeof(*addr)) == -1) {
		fprintf(stderr, "Failed to connect to socket: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

void *server_action_thread(void *data) {
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

		if (!serial_attached && state->action != PTY) {
			fprintf(stderr, "No serial port attached!\n");
			msg.type = MSG_ERR;
			strncpy(msg.info, "ERROR: No serial port attached!", sizeof(msg.info) - 1);
			goto respond;
		}

		switch (state->action) {
		case INVALID:
			fprintf(stderr, "Invalid action!\n");
			msg.type = MSG_ERR;
			strncpy(msg.info, "ERROR: Invalid action", sizeof(msg.info) - 1);
			break;
		case RESET:
			board_reset();
			msg.type = MSG_ACK;
			break;
		case BOOTLOADER:
			board_bootloader(monitor);
			msg.type = MSG_ACK;
			break;
		case UP:
			board_up();
			msg.type = MSG_ACK;
			break;
		case PWR:
			board_pwr();
			msg.type = MSG_ACK;
			break;
		case RELEASE:
			release_pwr();
			release_up();
			msg.type = MSG_ACK;
			break;
		case QUIT:
			release_pwr();
			release_up();
			msg.type = MSG_ACK;
		case PTY:
			msg.type = MSG_INFO;
			strncpy(msg.info, state->ptyname, sizeof(msg.info) - 1);
			break;
		case BAUD:
			if (set_baud(current_baud == B115200 ? B3000000 : B115200, false)) {
				msg.type = MSG_ERR;
				snprintf(msg.info, sizeof(msg.info) - 1, "ERROR: failed to set baud: %s", strerror(errno));
			} else {
				msg.type = MSG_INFO;
				snprintf(msg.info, sizeof(msg.info) - 1, "set baud %s", CURRENT_BAUD_STR);
			}
			break;
		default:
			fprintf(stderr, "Fell through!!!\n");
			break;
		}

respond:
		if (sendto(state->fd, &msg, sizeof(msg), 0, (struct sockaddr*)&state->addr_client, addrlen) < 0)
			fprintf(stderr, "Failed to send reply: %s\n", strerror(errno));
		pthread_mutex_unlock(&state->mutex);

		if (state->action == QUIT) {
			quit = true;
			notify = 0xff;
			write(notifyfd, &notify, sizeof(notify));
			break;
		}
	}

	udev_monitor_unref(monitor);
	udev_unref(udev);
	return NULL;
}

int handle_action(const char *port, struct rrst_action_state *state)
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
		memset(&msg, 0, sizeof(msg));
		break;
	default:
		fprintf(stderr, "Invalid message type: %d\n", msg.type);
		return -1;
	}

	if ((ret = pthread_mutex_trylock(&state->mutex)) == EBUSY) {
		msg.type = MSG_ERR;
		strncpy(msg.info, "ERROR: Action already in progress", sizeof(msg.info) - 1);
		if (sendto(state->fd, &msg, sizeof(msg), 0, (struct sockaddr*)&state->addr_client, addrlen) < 0)
			fprintf(stderr, "Failed to send reply: %s\n", strerror(errno));
	}

	if (ret) {
		fprintf(stderr, "Failed to lock mutex: %s\n", strerror(ret));
		quit = true;
		return -1;
	}

	printf("Handling action: '%s'\n", action_names[action]);
	state->action = action;

	pthread_cond_broadcast(&state->newaction);
	pthread_mutex_unlock(&state->mutex);

	return 0;
}

#define LINUX_TRANSITION "UEFI End"

int handle_tty(int fd)
{
	static char tty_line[4096];
	static int tty_line_len = 0;
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

	tty_line[tty_line_len++] = buf;
	if (buf == '\n' || buf == '\r') {
		if (strstr(tty_line, LINUX_TRANSITION)) {
			printf("Linux transition detected\n");
			set_baud(B3000000, false);
			set_baud(B3000000, false);
		}
		memset(tty_line, 0, sizeof(tty_line));
		tty_line_len = 0;
	}

	if (tty_line_len >= sizeof(tty_line)) {
		memset(tty_line, 0, sizeof(tty_line));
		tty_line_len = 0;
	}

	//printf("tty: %c\n", buf);

	wfd = ttyfd == fd ? ptyfd : ttyfd;
	ret = write(wfd, &buf, sizeof(buf));

	return 0;
}

int server_mainloop(const char *port)
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

	ttyfd = tp_open(port, reconnect_handler, (void*)port, 0);
	if(ttyfd == -1) {
		fprintf(stderr, "Error! opening %s\n", port);
		return errno;
	}

	ret = tp_flock(ttyfd, LOCK_EX);
	if (ret < 0) {
		if (errno == EWOULDBLOCK) {
			fprintf(stderr, "Error: Can't lock %s, another process is using it\n", port);
			//return errno;
		}

		fprintf(stderr, "Error: flock() failed: %s\n", strerror(errno));
	}

	release_pwr();
	release_up();

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

	set_baud(B115200, true);
	set_baud(B115200, true);

	if (pthread_create(&state.thread, NULL, server_action_thread, &state)) {
		fprintf(stderr, "Failed to create thread: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

#define N_FDS 4
	while (true) {
		struct pollfd fds[N_FDS];
		fds[0].fd = state.fd;
		fds[1].fd = notifyfd;
		fds[2].fd = ttyfd;
		fds[3].fd = ptyfd;
		for (int i = 0; i < N_FDS; i++)
			fds[i].events = POLLIN;

		//usleep(30000);

		if (poll(fds, N_FDS, -1) < 0) {
			fprintf(stderr, "Failed to select: %s\n", strerror(errno));
			ret = 1;
			goto out;
		}

		/* state.fd */
		if (fds[0].revents & POLLIN) {
			printf("state.fd\n");
			if (handle_action(port, &state) < 0) {
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
				printf("%s: %s\n", port, "Disconnected");
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

int do_action(enum actions action) 
{
	struct rrst_msg msg;
	int fd;
	struct sockaddr_un addr;
	struct sockaddr_un addr_client;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	int len;

	memset(&addr, 0, sizeof(addr));
	memset(&addr_client, 0, sizeof(addr_client));

	if (init_socket(&fd, &addr) < 0)
		return 1;

	addr_client.sun_family = AF_UNIX;
	snprintf(addr_client.sun_path, sizeof(addr_client.sun_path), SOCK_PATH, getuid(), getpid());
	strncpy(socket_path, addr_client.sun_path, sizeof(socket_path) - 1);

	//fprintf(stderr, "Using socket: %s\n", socket_path);

	if (bind_socket(fd, &addr_client) < 0) {
		close(fd);
		if (errno != EADDRINUSE)
			unlink(socket_path);
		return 1;
	}

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "RRST: Failed to connect to socket: %s\n", strerror(errno));
		close(fd);
		unlink(socket_path);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "RRST: Failed configure socket timeout: %s\n", strerror(errno));
		close(fd);
		unlink(socket_path);
		return 1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.type = MSG_ACTION;
	msg.action = action;

	if (send(fd, &msg, sizeof(msg), 0) == -1) {
		fprintf(stderr, "RRST: Failed to send message, is rrst running? %s\n", strerror(errno));
		close(fd);
		unlink(socket_path);
		return 1;
	}

	memset(&msg, 0, sizeof(msg));
	while ((len = recv(fd, &msg, sizeof(msg), 0)) == -1 && (errno == EINTR || errno == EAGAIN)) {
		usleep(1 * MS);
	}
	if (len == -1) {
		fprintf(stderr, "RRST: Failed to receive message, is rrst running? %s\n", strerror(errno));
		goto out;
	}

	switch (msg.type) {
	case MSG_ACK:
		printf("%s done!\n", action_names[action]);
		break;
	case MSG_ERR:
		printf("RRST: %s\n", msg.info);
		break;
	case MSG_INFO:
		printf("%s\n", msg.info);
		break;
	default:
		printf("RRST: Unexpected response type: %d\n", msg.type);
		break;
	}

out:
	close(fd);
	unlink(socket_path);
	return len > 0 ? 0 : 1;
}

int main(int argc, char *argv[])
{
	enum actions action = INVALID;

	int opt;
	char *port = NULL;
	while ((opt = getopt(argc, argv, "s:h")) != -1) {
		switch (opt) {
		case 's':
			port = optarg;
			break;
		case 'h':
			usage();
			return 127;
		default:
			usage();
			return 127;
		}
	}

	// Invoke an action
	if (optind < argc) {
		if (port) {
			fprintf(stderr, "Can't specify an action and a TTY device.\n");
			return 1;
		}
		action = parse_action(argv[optind++]);
	} else if (!port) {
		fprintf(stderr, "No arguments specified!\n");
		usage();
		return 1;
	} else {
		/* Spawn server */
		return server_mainloop(port);
	}

	/* Client */
	return do_action(action);
}
