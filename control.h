#pragma once

#include <stdbool.h>

#include "rrst.h"
#include "config.h"

struct rrst_control {
        /* Optional first time init */
        int (*init)(struct rrst_config *config);
        void (*exit)(void);
        void (*on_connect)(bool serial_attached);
        int (*reset)(struct rrst_msg *msg);
        /* Do the actions needed to boot to bootloader, don't block */
        int (*start_bootloader)(struct rrst_msg *msg);
        int (*up)(struct rrst_msg *msg);
        int (*pwr)(struct rrst_msg *msg);
        /* Release all buttons (also called after start_bootloader() when fastboot detected) */
        int (*release)(struct rrst_msg *msg);
};

extern struct rrst_control rts_dtr_control;
extern struct rrst_control qcom_dbg_control;
