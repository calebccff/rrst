#pragma once

#include <termios.h>

enum rrst_control_method {
	RRST_CONTROL_NONE,
	RRST_CONTROL_RTS_DTR,
	RRST_CONTROL_QCOM_DBG,
};

struct rrst_config {
	char *name;
	char *port;
	speed_t baud_bootloader;
	speed_t baud_linux;
	char *linux_detect;
	enum rrst_control_method control_method;
	char *control_port; /* qcom_dbg only */
};

int rrst_load_config(const char *path, struct rrst_config *config);
