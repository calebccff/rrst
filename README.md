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
rrst (-s /dev/ttyUSB0|reset|bootloader|up|pwr)
        -s             : run daemon on a given port
        reset          : reset the board
        bootloader     : enter bootloader mode
        up             : press the up button (serial RTS pin)
        pwr            : press the power button (serial DTR pin)
        release        : release all buttons
```

## Running alongside a serial program

Ensure your program doesn't lock the TTY device, and that it avoids touching the
RTS and DTR lines. I use `picocom` with the following arguments:

```bash
picocom -l --noinit --noreset --lower-rts --lower-dtr
```

## Wiring

Ensure your serial adapter is 1.8v (and is 1.8v on the DTR/RTS lines). Use a
5-10k resistor between the button test pad and the pins to prevent the pullups
in the serial adapter from interfering with normal usage.

## Compilation

```bash
make rrst
```

## Systemd services

The `uart.path` and `rrstwatch.service` units can be installed as systemd user
services by symlinking to `/etc/xdg/systemd/user/`, enable `uart.path` to have
`rrst` automatically launch in the background whenever `ttyUSB0` is available.