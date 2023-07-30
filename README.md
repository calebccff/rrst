# Remote ReSeT

RRST is a daemon for controlling an individual board via either the RTS and DTR
pins of a standard USB->UART adapter, or via an external MCU implementing the
[CDBA](https://github.com/andersson/cdba) control interface.

RRST expects your board to have a power button and a  "bootloader mode" button
(usually volume up). You should attach these to the DTR# and RTS pins
respectively, ideally though a ~10k+ resister (4.7k will do fine).

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

Baud rates can be configured in the configuration file. It's also possible to
configure two baud rates, one for the bootloader and one for Linux. This lets
the kernel boot a looot faster by using a high baud rate like 3000000 without
missing out on bootloader messages. This is accomplished by doing substring
searching on the serial output from the device and switching to the Linux baud
rate when a match is found. The baud rate can also be toggle with `rrst baud`.

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
