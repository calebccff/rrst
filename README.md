# Rts ReSeT

Use the RTS and DTR# pins of a UART adapter to control qualcomm boards.

RRST expects your board to have a power button and a  "bootloader mode" button
(usually volume up). You should attach these to the DTR# and RTS pins
respectively, ideally though a ~10k+ resister (4.7k will do fine).

The reason for the user service is a workaround for the FTDI Linux drivers as
they will unconditionally reset the RTS and DTR# pins when you call `open()` on
the serial device... Simiarly when attaching the device the pins are reset. The
service handles this by opening the device as soon as it's available and
releasing the pins.

## Usage

```txt
rrst (-s /dev/ttyUSB0|reset|bootloader|up|pwr|pty|baud)
        -s             : run daemon on a given port
        reset          : reset the board
        bootloader     : enter bootloader mode
        up             : press the up button (serial RTS pin)
        pwr            : press the power button (serial DTR pin)
        release        : release all buttons
        pty            : get the pty path for your serial console
        baud           : toggle the serial baud manually (115200/3000000)
```

## Running a serial monitor

To implement smooth baud rate changes, and workaround the FTDI quirk, rrst
provides a passthrough terminal on a pty. As a bonus, this uses
[ttypersist](https://github.com/russdill/ttypersist), which caches serial port
configuration and hides disconnect/reconnect events, so you can safely
detach/reattach your serial adapter without your monitor program disconnecting.

The pty path can be retrieved with `rrst pty`, this can be integrated into a oneliner like:

```sh
picocom $(rrst pty)
```

## Baud rates

FIXME: currently the baud rates are hardcoded, 115200 when in the bootloader and
3000000 in Linux. The bootloader -> Linux transition is detected by string
matching against "UEFI end", the string in Qcom bootloadlers. Linux ->
bootloader transition is triggered by the rrst `reset` and `bootloader`
commands. The baud rate can be toggle with `rrst baud`, I recommend configuring
these as global shortcuts in your window manager or DE.

## Wiring

Ensure your serial adapter is 1.8v (and is 1.8v on the DTR/RTS lines). Use a
5-10k resistor between the button test pad and the pins to prevent the pullups
in the serial adapter from interfering with normal usage.

## Compilation

```bash
meson setup build
meson compile -C build
```

Install with

```sh
sudo meson install -C build
```

## Systemd services

RRST provides a user service to run the daemon, you can configure the serial
port in `$HOME/.config/rrst.conf`, see the default config in this repo.
