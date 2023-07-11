## What it does?

This kernel module hooks into the pf(packet filter) firewall of FreeBSD 13.1 and detects if there are TCP/UDP packets inbound greater than or equal to port 1024.
This module also detects any ping scans from remote hosts.

## How to load this module?

Simply run the following command
```
make load
```

### How to unload this module?

Simple run the following command
```
make unload
```

Note: This repository does not contain kernel headers. Look into their wiki to know how to build kernel modules for freebsd.
