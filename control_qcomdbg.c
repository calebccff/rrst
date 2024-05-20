#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "rrst.h"
#include "ttypersist.h"
#include "control.h"
#include "config.h"

static const char *control_port;
static bool control_port_attached = false;
static int cfd = -1;
static enum qcom_dbg_type qcom_dbg_type;
static const char *board_name;

#define write_byte(b) if (write(cfd, b, 1) != 1) RRST_MSG_ERR_RET(msg, "ERROR: failed to write '" b "' to control port\n")

#define press_pwr() do { printf("press_pwr\n"); write_byte("B"); } while (0)
#define release_pwr() do { printf("release_pwr\n"); write_byte("b"); } while (0)
#define press_up() do { printf("press_up\n"); write_byte("R"); } while (0)
#define release_up() do { printf("release_up\n"); write_byte("r"); } while (0)
#define enable_power() do { printf("enable_power\n"); write_byte("P"); } while (0)
#define disable_power() do { printf("disable_power\n"); write_byte("p"); } while (0)
#define enable_vbus() do { printf("enable_vbus\n"); write_byte("U"); } while (0)
#define disable_vbus() do { printf("disable_vbus\n"); write_byte("u"); } while (0)

static void control_port_reconnect(void *data, int fd) {
	control_port_attached = fd > 0;

	if (control_port_attached) {
		printf("control port connectected\n");
		return;
	}
}

static int qcom_dbg_init(struct rrst_config *config) {
	control_port = config->control_port;
	qcom_dbg_type = config->qcom_dbg_type;
	board_name = config->name;

	cfd = tp_open(control_port, control_port_reconnect, NULL, 0);
	if (cfd == -1) {
		fprintf(stderr, "ERROR: failed to open control port %s: %s\n", control_port, strerror(errno));
		return errno;
	}

	printf("Using control port %s\n", control_port);

	_set_baud(cfd, B115200, true);

	// Enable power all the time, just in case
	if (qcom_dbg_type == QCOM_DBG_TYPE_NOPWR)
		write(cfd, "P", 1);

	return 0;
}

static void qcom_dbg_exit() {
	if (cfd != -1) close(cfd);
}

static void qcom_dbg_on_connect(bool serial_attached) {
	/* */
}

static int qcom_dbg_release_btns(struct rrst_msg *msg) {
	//disable_power();
	//disable_vbus();
	release_pwr();
	release_up();

	RRST_MSG_ACK(msg);
}

/* No fiddling with button combos \o/ */
static int qcom_dbg_board_reset_start(struct rrst_msg *msg) {
	print_serial("RRST: Resetting device...");
	switch (qcom_dbg_type) {
	case QCOM_DBG_TYPE_NORMAL:
		disable_power();
		disable_vbus();
		usleep(300 * MS);
		enable_power();
		usleep(10 * MS);
		enable_vbus();
		press_up();
		break;
	case QCOM_DBG_TYPE_NOPWR:
		// For boards without power control, do it the hard way
		press_pwr();
		if (!strncmp(board_name, "axolotl", strlen("axolotl")))
			usleep(11500 * MS);
		else /* XXX: op6 needs more */
			usleep(14000 * MS);
		print_serial("RRST: Press up...");
		press_up();
		usleep(1000 * MS);
		print_serial("RRST: Release pwr...");
		release_pwr();
		break;
	}

	RRST_MSG_ACK(msg);
}

static int qcom_dbg_board_reset(struct rrst_msg *msg) {
	if (qcom_dbg_board_reset_start(msg)) return -1;
	release_up();
	disable_vbus();
	print_serial("RRST: Release up");

	return 0;
}

static int qcom_dbg_board_pwr(struct rrst_msg *msg) {
	print_serial("RRST: Press pwr");
	press_pwr();
	usleep(50 * MS);
	release_pwr();

	RRST_MSG_ACK(msg);
}

static int qcom_dbg_board_up(struct rrst_msg *msg) {
	print_serial("RRST: press up");
	press_up();
	usleep(50 * MS);
	release_up();

	RRST_MSG_ACK(msg);
}

struct rrst_control qcom_dbg_control = {
	.init = qcom_dbg_init,
	.on_connect = qcom_dbg_on_connect,
	.release = qcom_dbg_release_btns,
	.reset = qcom_dbg_board_reset,
	.start_bootloader = qcom_dbg_board_reset_start,
	.up = qcom_dbg_board_up,
	.pwr = qcom_dbg_board_pwr,
	.exit = qcom_dbg_exit,
};
