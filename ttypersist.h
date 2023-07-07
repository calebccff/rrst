#pragma once

typedef void (reconnect_cb)(void *priv, int fd);

int tp_open(const char *pathname, reconnect_cb *cb, void *priv, int flags, ...);
int tp_ioctl(int d, unsigned long int request, ...);
int tp_flock(int d, int operation);