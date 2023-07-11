# signsky.

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
The processes share packets between each other in a very well defined way.

For incoming packets:

```
crypto -> -> decrypt -> clear
```

For outgoing packets:

```
clear -> encrypt -> crypto
```

Each process is sandboxed and only has access to the system calls
required to perform its task.

## Traffic

The encrypted traffic is encapsulated with ESP in tunnel mode.

## Building

TODO
