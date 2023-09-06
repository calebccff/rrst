#pragma once

#include <stdbool.h>
#include <termios.h>
#include <string.h>

#define MS 1000

enum actions {
	INVALID = 0,
	RESET,
	BOOTLOADER,
	UP,
	PWR,
	RELEASE,
	PTY,
	BAUD,
	TEST,
	UART,
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
	enum actions action;
	char info[128];
	char info2[128];
};

/* Common error path, set msg info str, print error and return. 
 * Used in control_* implementations
 */
#define RRST_MSG_ERR_RET(msg, str) do { \
		fprintf(stderr, "%s\n", str); \
		if ((msg)) { \
			(msg)->type = MSG_ERR; \
			strncpy((msg)->info, str, sizeof((msg)->info) - 1); \
		} \
		return -1; \
	} while (0)

#define RRST_MSG_ACK(msg) do { \
		if ((msg)) { \
			(msg)->type = MSG_ACK; \
		} \
		return 0; \
	} while (0)

extern int ttyfd;
extern bool quit;

int _set_baud(int fd, speed_t speed, bool make_raw);
void print_serial(const char *fmt, ...);
