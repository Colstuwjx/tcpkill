# tcpkill

Golang version of dsniff tcpkill with some feature enhancements.

## Prerequisite

on CentOS:

```
yum install -y libpcap-devel
```

on Ubuntu:

```
apt-get install -y libpcap-dev
```

## TODOs

- [x] works like `tcpkill`

- [ ] support `-i any`

## NOTE

Initially forked from [tcpwall](https://github.com/dushixiang/tcpwall) and inspired from [tcpkill](https://github.com/ggreer/dsniff/blob/master/tcpkill.c).

## Why not use tcpwall directly?

1. it didn't support full bpf filter expression
2. customize requirement from my own
