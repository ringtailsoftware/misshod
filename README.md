# MiSSHod

*misshod. (ˌmɪsˈʃɒd). adj. badly shod*

# About

MiSSHod is a minimal, experimental SSH client and server implemented as a library.

It has been tested with both [OpenSSH](https://github.com/openssh/openssh-portable) and [Dropbear](https://github.com/mkj/dropbear).

**MiSSHod is not secure, it should not be used in real world systems**

It aims to be:

 - Transport and I/O agnostic - TCP would be normal, but MiSShod can be run over any reliable stream protocol
 - Asynchronous - MiSShod never blocks execution for I/O, it enters a wait state and can be resumed when data arrives
 - Callback free - asynchronous message passing prevents the caller needing callbacks and context structs
 - Very lightweight, opening up the possibility of running on small embedded devices

**Features**

 - Public key auth
 - Password auth
 - Supports exactly one of each of the required protocols
    - hmac-sha2-256 (hmac)
    - curve25519-sha256 (key exchange)
    - ssh-ed25519 (key)
    - aes256-ctr (cipher)

# Building

MiSSHod requires [Zig 0.14.0](https://ziglang.org/download/). 

## Client

To build `mssh`, a command line SSH client for Mac/Linux

```bash
zig build test
```

```bash
cd mssh
zig build
./zig-out/bin/mssh
./zig-out/bin/mssh <username@host> <port> [idfile]
```

To run a test SSH server (dropbear) in docker

```bash
cd testserver
./sshserver
```

Login with password auth, ("password")

```bash
./zig-out/bin/mssh testuser@127.0.0.1 2022
# Same as: ssh -p 2022 testuser@127.0.0.1
```

Login with pubkey auth using a passwordless private key

```bash
./zig-out/bin/mssh testuser@127.0.0.1 2022 ../testserver/id_ed25519_passwordless
# Same as: ssh -p 2022 testuser@127.0.0.1 -i ../testserver/id_ed25519_passwordless
```

Login with pubkey auth using a password protected private key ("secretpassword")

```bash
./zig-out/bin/mssh testuser@127.0.0.1 2022 ../testserver/id_ed25519_passworded
# Same as: ssh -p 2022 testuser@127.0.0.1 -i ../testserver/id_ed25519_passworded
```

## Server

`msshd` is a toy ssh server. It handles one connection at a time and echoes back received data with "You said X".

To build `msshd`

```bash
cd msshd
zig build
./zig-out/bin/msshd
./zig-out/bin/msshd <port> <hostkey>
```

To run the server

```bash
./zig-out/bin/msshd 2022 ../testserver/id_ed25519_passwordless
Server listening on port 2022
```

Connect using OpenSSH

```bash
ssh -p 2022 foo@127.0.0.1
```

By default the server will accept any public key offered. Typically, OpenSSH offers all available keys, so it will be able to login immediately. This can be changed in `msshd/src/main.zig`. Typically, a real server would check the user's `authorized_keys` file.

Connect using `mssh` using pubkey auth (key password is "secretpassword")

```bash
cd mssh
zig build run -- foo@127.0.0.1 2022 ../testserver/id_ed25519_passworded
```

Connect using `mssh` using password auth (any password matching username will be accepted, so "foo" here)

```bash
cd mssh
zig build run -- foo@127.0.0.1 2022
```


# Tiny client example

As a proof of concept, the `tiny` example logs into the test server but contains no socket code. Instead, it uses stdout and stdin. To run it via `socat`:

```bash
zig build && socat TCP4:127.0.0.1:2022 EXEC:./zig-out/bin/tiny
```

Tiny uses a weaker PRNG, a fixed buffer allocator and does no file I/O.

# Security

**MiSSHod is not secure, it should not be used in real world systems**

 - Very little testing has been done and not all code paths have been exercised
 - No efforts have been made to prevent timing attacks
 - Sensitive data is held in RAM for longer than is strictly necessary
 - MiSSHod relies on Zig's standard library for all crypto algorithms, which is still relatively young
 - Most importantly, I am not a cryptographer and I have no idea what I'm doing

# Status

MiSSHod was developed rapidly. The main aim was to get it working and learn something along the way. I don't know what's next, but hopefully you can learn something too by looking at a small SSH implementation.

It's entirely undocumented and there aren't enough tests. The IO systems are a bit arcane, as I've tried wherever possible to avoid using excess RAM.

