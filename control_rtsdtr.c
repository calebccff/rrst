#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "rrst.h"
#include "ttypersist.h"
#include "control.h"
#include "config.h"

static int rts = TIOCM_RTS, dtr = TIOCM_DTR;
static bool serial_attached = false;

#define btn_pwr (dtr) // set to press
#define btn_up (rts) // clear to press

#define btn_name(btn) (btn == btn_pwr ? "power" : "up")

static void press_btn(int btn) {
	if (!serial_attached) return;
	if (!quit) printf("%s: press\n", btn_name(btn));
	tp_ioctl(ttyfd, TIOCMBIS, &btn);
}

static void release_btn(int btn) {
	if (!serial_attached) return;
	if (!quit) printf("%s: release\n", btn_name(btn));
	tp_ioctl(ttyfd, TIOCMBIC, &btn);
}

#define press_pwr() press_btn(btn_pwr)
#define press_up() press_btn(btn_up)
#define release_pwr() release_btn(btn_pwr)
#define release_up() release_btn(btn_up)

static int rts_dtr_start_reset_set_baud(struct rrst_msg *msg)
{
	if (!serial_attached)
		RRST_MSG_ERR_RET(msg, "ERROR: no serial port attached\n");

	press_pwr();
	press_up();
	/* Give enough time for the hard reset before the baud rate gets changed */
	usleep(10500 * MS);

	RRST_MSG_ACK(msg);
}

static int rts_dtr_board_release(struct rrst_msg *msg) {
	if (!serial_attached)
		RRST_MSG_ERR_RET(msg, "ERROR: no serial port attached\n");

	release_pwr();
	release_up();

	RRST_MSG_ACK(msg);
}

// Hold power and volume up for 10.5 seconds
// release volume up and hold power for 1.5 seconds
static int rts_dtr_board_reset(struct rrst_msg *msg) {
	if (!serial_attached)
		RRST_MSG_ERR_RET(msg, "ERROR: no serial port attached\n");

	rts_dtr_start_reset_set_baud(msg);
	rts_dtr_board_release(msg);

	RRST_MSG_ACK(msg);
}

static void rts_dtr_on_connect(bool _serial_attached) {
	serial_attached = _serial_attached;
	if (serial_attached) {
		printf("Reconnected\n");
		rts_dtr_board_release(NULL);
	}
}

static int rts_dtr_board_up(struct rrst_msg *msg) {
	if (!serial_attached)
		RRST_MSG_ERR_RET(msg, "ERROR: no serial port attached\n");

	press_up();
	usleep(50 * MS);
	release_up();

	RRST_MSG_ACK(msg);
}

static int rts_dtr_board_pwr(struct rrst_msg *msg) {
	if (!serial_attached)
		RRST_MSG_ERR_RET(msg, "ERROR: no serial port attached\n");

	press_pwr();
	usleep(50 * MS);
	release_pwr();

	RRST_MSG_ACK(msg);
}

struct rrst_control rts_dtr_control = {
	.on_connect = rts_dtr_on_connect,
	.release = rts_dtr_board_release,
	.reset = rts_dtr_board_reset,
	.start_bootloader = rts_dtr_start_reset_set_baud,
	.up = rts_dtr_board_up,
	.pwr = rts_dtr_board_pwr,
};
