#include <ini.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include "config.h"

#define load_key_or_ret(key) \
do { \
	if (strcmp(name, #key) == 0) { \
		if (config->key) \
			free(config->key); \
		config->key = strdup(value); \
		printf("config: %s = %s\n", name, value); \
		return 1; \
	} \
} while (0)

#define load_baud_key_or_ret(key) \
do { \
	if (strcmp(name, #key) == 0) { \
		if (!strcmp(value, "115200")) \
			config->key = B115200; \
		else if (!strcmp(value, "3000000")) \
			config->key = B3000000; \
		else { \
			fprintf(stderr, "Unknown baud rate: %s\n", value); \
			return 1; \
		} \
		printf("config: %s = %s\n", name, value); \
		return 1; \
	} \
} while (0)


static int config_handler(void *ud, const char *section, const char *name,
			  const char *value)
{
	if (strcmp(section, "rrst") != 0)
		return 0;
	struct rrst_config *config = ud;

	//printf("config: %s = %s\n", name, value);

	load_key_or_ret(name);
	load_key_or_ret(port);
	load_baud_key_or_ret(baud_bootloader);
	load_baud_key_or_ret(baud_linux);
	load_key_or_ret(linux_detect);
	load_key_or_ret(control_port);

	if (strcmp(name, "control_method") == 0) {
		if (strcmp(value, "rts_dtr") == 0) {
			config->control_method = RRST_CONTROL_RTS_DTR;
			return 0;
		} else if (strcmp(value, "qcom_dbg") == 0) {
			config->control_method = RRST_CONTROL_QCOM_DBG;
			return 0;
		} else {
			fprintf(stderr, "Unknown control method: %s\n", value);
			return 1;
		}
	}

	return 0;
}

int rrst_load_config(const char *path, struct rrst_config *config) {
	if (ini_parse(path, config_handler, config) < 0) {
		return -1;
	}
	if (!config->name) {
		fprintf(stderr, "name not specified in config\n");
		return -1;
	}
	if (!config->port) {
		fprintf(stderr, "port not specified in config\n");
		return -1;
	}
	if (!config->baud_bootloader) {
		fprintf(stderr, "baud_bootloader not specified in config\n");
		return -1;
	}
	if (!config->baud_linux && config->linux_detect) {
		fprintf(stderr, "baud_linux not specified in config but linux_detect was\n");
		return -1;
	}
	if (!config->control_method) {
		fprintf(stderr, "control_method not specified in config\n");
		return -1;
	}
	if (config->control_method == RRST_CONTROL_QCOM_DBG && !config->control_port) {
		fprintf(stderr, "control_port not specified in config\n");
		return -1;
	}

	return 0;
}