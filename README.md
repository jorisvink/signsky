# signsky

## About

<img src="signsky.png" alt="signsky" width="128px" />

This is a very small, reviewable and fully privilege seperated VPN daemon
capable of transporting network traffic between two peers.

This is still a work in progress and is not considered done yet.

## Privilege separation

signsky consists of 5 processes:

| Process name | Description  |
| ------------ | ------------ |
| encrypt | the process responsible for encrypting packets.
| decrypt | the process responsible for decrypting packets.
| keying | the process responsible for deriving new TX/RX keys from a key.
| clear | the process receiving and sending packets on the inner interface.
| crypto | the process receiving and sending packets on the outer interface.

Each process can run as its own user.

Each process is sandboxed and only has access to the system calls
required to perform its task.

## Packets

The processes share packets between each other in a very well defined way.

For incoming packets:

```
crypto -> decrypt -> clear
```

For outgoing packets:

```
clear -> encrypt -> crypto
```

Due to the design of signsky it is impossible to move a packet straight
from the clear side to the crypto side without passing the encryption
process.

## Traffic

The encrypted traffic is encapsulated with ESP in tunnel mode, using
64-bit sequence numbers and encrypted under AES256-GCM using keys
derived from a shared symmetrical key.

## High performance mode

When signsky is built with the CIPHER=intel-aes-gcm and HPERF=1,
high performance mode is enabled.

In this mode, signsky is able to reach 10gbps speeds, depending on hardware.

## Building

TODO
