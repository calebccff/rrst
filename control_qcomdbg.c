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

#define write_byte(b) if (write(cfd, b, 1) != 1) RRST_MSG_ERR_RET(msg, "ERROR: failed to write '" b "' to control port\n")

#define press_pwr() write_byte("B")
#define release_pwr() write_byte("b")
#define press_up() write_byte("R")
#define release_up() write_byte("r")
#define enable_power() write_byte("P")
#define disable_power() write_byte("p")
#define enable_vbus() write_byte("U")
#define disable_vbus() write_byte("u")

static void control_port_reconnect(void *data, int fd) {
	control_port_attached = fd > 0;

	if (control_port_attached) {
		printf("control port connectected\n");
		return;
	}
}

static int qcom_dbg_init(struct rrst_config *config) {
	control_port = config->control_port;

	cfd = tp_open(control_port, control_port_reconnect, NULL, 0);
	if (cfd == -1) {
		fprintf(stderr, "ERROR: failed to open control port %s: %s\n", control_port, strerror(errno));
		return errno;
	}

	printf("Using control port %s\n", control_port);

	_set_baud(cfd, B9600, true);

	return 0;
}

static void qcom_dbg_exit() {
	if (cfd != -1) close(cfd);
}

static void qcom_dbg_on_connect(bool serial_attached) {
	/* */
}

static int qcom_dbg_release_btns(struct rrst_msg *msg) {
	enable_power();
	usleep(10 * MS);
	enable_vbus();
	release_pwr();
	release_up();

	RRST_MSG_ACK(msg);
}

/* No fiddling with button combos \o/ */
static int qcom_dbg_board_reset(struct rrst_msg *msg) {
	disable_power();
	disable_vbus();
	usleep(300 * MS);
	enable_power();
	usleep(10 * MS);
	enable_vbus();

	RRST_MSG_ACK(msg);
}

/* Reset the board and then hold UP to get to fastboot */
static int qcom_dbg_reset_enter_bootloader(struct rrst_msg *msg) {
	if (qcom_dbg_board_reset(msg)) return -1;
	press_up();

	RRST_MSG_ACK(msg);
}

static int qcom_dbg_board_pwr(struct rrst_msg *msg) {
	press_pwr();
	usleep(50 * MS);
	release_pwr();

	RRST_MSG_ACK(msg);
}

static int qcom_dbg_board_up(struct rrst_msg *msg) {
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
	.start_bootloader = qcom_dbg_reset_enter_bootloader,
	.up = qcom_dbg_board_up,
	.pwr = qcom_dbg_board_pwr,
	.exit = qcom_dbg_exit,
};
