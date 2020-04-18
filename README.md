# simple sniffer on LAN

This scanner is only available on Linux, do not try to run it on Windows and WSL cause the latter do not support physical network adapter. Also not recommended on other Unix distributions.


## Building

1. make

```bash
$ make
```

2. clean files

```bash
$ make clean
```


## Usage

launch the sniffer:

```bash
$ sudo ./sniffer
```

enter name of the interface, it will be set to promiscuous mode.

```bash
Interface name:[Interface name]
Interface name:wlan0
```

press `control-C` to stop, results will be saved in `log.txt`.
