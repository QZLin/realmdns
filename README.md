# Real mDNS

## Name

Real mDNS -- A CoreDNS plugin that reads mDNS records from the local network and responds
to queries based on those records.

## Description

Useful for providing mDNS records to non-mDNS-aware applications by making them
accessible through a standard DNS server.

## Syntax

```
realmdns [bind address]
```

## Examples

``` corefile
local.:53 {
    realmdns
}
.:53 {
    forward . 1.1.1.1 8.8.8.8
}
```

And test with `dig`:

``` txt
dig @localhost test.local

;; ANSWER SECTION:
test.local. 60 IN A   10.0.0.1
test.local. 60 IN AAAA fe80::abcd:abcd:abcd:abcd
```

Example corefile for tests:

```corefile
local.:54 {
    log
    debug
    realmdns
    errors
}

.:54 {
    forward . 1.1.1.1 8.8.8.8
    cache
    log
    errors
}

```

Test with dig ipv4/ipv6

```txt
dig -p 54 '@127.0.0.1' test.local
dig -p 54 '@127.0.0.1' test.local AAAA
```
