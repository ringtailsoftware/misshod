# An SSH Protocol Primer

I use SSH every day. I login to remote machines, push code changes to github and scp files.
Like many programmers, I know how to use SSH to get things done but had never looked deeper to understand the protocol itself.

I recently wrote a [minimal SSH](https://github.com/ringtailsoftware/misshod) client to help demystify the protocol. In this post, I'll explain some of the core concepts to help anyone else doing the same. This will be a 10,000ft overview with references to some interesting parts - not an implementation guide.

SSH was designed as a replacement for the venerable telnet. Back in the day, we really would just open a TCP socket and type our password in plaintext to gain access to remote machines. It's probably clear why something more secure is needed for the modern Internet age.

## Getting started

Rather than reading the source of an existing client or trying to read all of the RFCs first (ugh...), let's connect to a server and see what we get. SSH servers listen on port 22, we can connect a TCP socket using netcat.

```bash
nc localhost 22
SSH-2.0-OpenSSH_9.7
```

We're greeted by what looks like a version string, "SSH-2.0-OpenSSH_9.7" and then silence. It's waiting for a response. Let's say hello by echoing back the same version string.

```bash
nc localhost 22
SSH-2.0-OpenSSH_9.7
SSH-2.0-OpenSSH_9.7
\�v�� 'H��Lyu�`9�1sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com9rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.comlchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com�umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1�umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1none,zlib@openssh.comnone,zlib@openssh.com
```

Bingo, some interesting garbage. Let's look at the bytes in hex

```bash
echo "SSH-2.0-OpenSSH_9.7" | nc localhost 22 | xxd | head
00000000: 5353 482d 322e 302d 4f70 656e 5353 485f  SSH-2.0-OpenSSH_
00000010: 392e 370d 0a00 0004 5c07 144c faa7 9540  9.7.....\..L...@
00000020: 4678 3bad 729f 66d8 d2f6 7800 0001 3173  Fx;.r.f...x...1s
00000030: 6e74 7275 7037 3631 7832 3535 3139 2d73  ntrup761x25519-s
00000040: 6861 3531 3240 6f70 656e 7373 682e 636f  ha512@openssh.co
00000050: 6d2c 6375 7276 6532 3535 3139 2d73 6861  m,curve25519-sha
00000060: 3235 362c 6375 7276 6532 3535 3139 2d73  256,curve25519-s
00000070: 6861 3235 3640 6c69 6273 7368 2e6f 7267  ha256@libssh.org
00000080: 2c65 6364 682d 7368 6132 2d6e 6973 7470  ,ecdh-sha2-nistp
00000090: 3235 362c 6563 6468 2d73 6861 322d 6e69  256,ecdh-sha2-ni
```

The server version string ends in the bytes 0x0D 0x0A or "\r\n". "SSH-2.0-OpenSSH_9.7\r\n". Then, we have some sort of binary packet. It looks like we *will* have to read the RFCs, but I'll highlight the important parts. It's described in [RFC-4253 The Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253#section-6)

	Each packet is in the following format:
	
	      uint32    packet_length
	      byte      padding_length
	      byte[n1]  payload; n1 = packet_length - padding_length - 1
	      byte[n2]  random padding; n2 = padding_length
	      byte[m]   mac (Message Authentication Code - MAC); m = mac_length

Now we can decode the first bytes after the server version. `{0x00, 0x00, 0x04, 0x5c}` will be the `uint32 packet_length`.

If you've encountered binary network protocols before you'll spot that this `uint32` value is read from right to left. So, the value is (0x5c * 1<<0) + (0x04 * 1<<8) + (0x00 * 1<<16) + (0x00 * 1<<24) = 1116. That fits with the amount of data we received.

If you didn't know that [network byte order is always big-endian](https://www.rfc-editor.org/ien/ien137.txt) even though virtually all popular CPU architectures are now little endian then you may want to pause for a moment to weep in the corner for the wasted CPU cycles.

Done? Good. After our `uint32 packet_length` we have a single byte telling us the `padding_length` (0x07) and now we're reading the `payload`.

The length of the payload we're told is `packet_length - padding_length - 1`, so 1116 - 7 - 1 = 1108 and we can see from the hex that it starts `{0x14, 0x4c, ...}`.

Looking at the ASCII of that first packet, we see lots of encryption algorithm names. [The RFC tells us that it's an algorithm negotiation](https://datatracker.ietf.org/doc/html/rfc4253#section-7.1).

	Key exchange begins by each side sending the following packet:
	
	      byte         SSH_MSG_KEXINIT
	      byte[16]     cookie (random bytes)
	      name-list    kex_algorithms
	      name-list    server_host_key_algorithms
	      name-list    encryption_algorithms_client_to_server
	      name-list    encryption_algorithms_server_to_client
	      name-list    mac_algorithms_client_to_server
	      name-list    mac_algorithms_server_to_client
	      name-list    compression_algorithms_client_to_server
	      name-list    compression_algorithms_server_to_client
	      name-list    languages_client_to_server
	      name-list    languages_server_to_client
	      boolean      first_kex_packet_follows
	      uint32       0 (reserved for future extension)

Our first payload byte was 0x14 which corresponds to `SSH_MSG_KEXINIT`. [RFC-4250](https://datatracker.ietf.org/doc/html/rfc4250#section-4.1.2) confirms it.

    Message ID                            Value    Reference
    -----------                           -----    ---------
    SSH_MSG_KEXINIT                         20     [SSH-TRANS]

Now, we can start to break down the rest of this packet. 

	00000010:                          144c faa7 9540            .L...@
	00000020: 4678 3bad 729f 66d8 d2f6 7800 0001 3173  Fx;.r.f...x...1s
	00000030: 6e74 7275 7037 3631 7832 3535 3139 2d73  ntrup761x25519-s
	00000040: 6861 3531 3240 6f70 656e 7373 682e 636f  ha512@openssh.co
	00000050: 6d2c 6375 7276 6532 3535 3139 2d73 6861  m,curve25519-sha

After `SSH_MSG_KEXINIT` (0x14), we get 16 bytes of random `cookie`. Before a `name-list` of `kex-algorithms`.

	00000020:                            00 0001 3173             ...1s
	00000030: 6e74 7275 7037 3631 7832 3535 3139 2d73  ntrup761x25519-s
	00000040: 6861 3531 3240 6f70 656e 7373 682e 636f  ha512@openssh.co
	00000050: 6d2c 6375 7276 6532 3535 3139 2d73 6861  m,curve25519-sha

So, our `name-list` starts with the bytes 0x00, 0x01, 0x01 ...

[RFC-4251](https://datatracker.ietf.org/doc/html/rfc4251#section-5) tells us that a `name-list` is

	A string containing a comma-separated list of names.  A name-list
   is represented as a uint32 containing its length (number of bytes
   that follow) followed by a comma-separated list of zero or more
   names.

The first four bytes of our name-list are its length encoded as a (big-endian, of course) uint32. `{0x00, 0x00, 0x01, 0x31}` gives us 305 bytes. And in those next 305 bytes we receive a comma separated list of algorithm names. `sntrup761x25519-sha512@openssh.com,curve25519-sha256,...`.

Now, we can follow exactly the same process for all of the other fields and decode the entire packet. The `boolean`, according to [RFC-4251](https://datatracker.ietf.org/doc/html/rfc4251#section-5) is a single byte where 0 = FALSE and any other value = TRUE.

Looking again at [RFC-4253 The Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253#section-6) to check the packet format. We've now fully consumed the payload bytes (`byte[n1]`). Following this are some random padding (`byte[n2]`) which we can skip and discard. Finally there is `byte[m]` which for now will be zero length.

Amazing. To recap - we've connected to an SSH server, exchanged protocol versions ("SSH-2.0-OpenSSH_9.7\r\n") then received and decoded our first packet. The packet contained a fixed sized header of 5 bytes (uint32 packet_length, byte padding_length), a payload and some padding bytes. The first byte of the payload was a [message id](https://datatracker.ietf.org/doc/html/rfc4250#section-4.1.2) telling us how to decode the payload using the types from [RFC-4251](https://datatracker.ietf.org/doc/html/rfc4251#section-5).

After sending the `SSH_MSG_KEXINIT` packet, the SSH server is waiting for a response. As [RFC-4253](https://datatracker.ietf.org/doc/html/rfc4253#section-7.1) tells us, both sides are expected to send an `SSH_MSG_KEXINIT` packet.

## Helper functions

Now that we have a grasp on how to decode a packet, we can use exactly the same logic to construct our own.
But, before we do that - let's look at some code I'm using to make handling SSH packets easier. Here is an extract from my [`BufferReader`](https://github.com/ringtailsoftware/misshod/blob/main/src/buffer.zig).

The `init` function takes a slice of bytes and starts the offset `off` at 0. Each other function then attempts to read from the current offset, returning an error if there isn't enough data. We can now safely chew through incoming packets.

```zig
pub const BufferReader = struct {
    const Self = @This();
    payload: []const u8,
    off: usize,

    pub fn init(payload: []const u8) Self {
        return Self{
            .payload = payload,
            .off = 0,
        };
    }

    pub fn readU8(self: *Self) BufferError!u8 {
        if (self.off + 1 > self.payload.len) {
            return BufferError.ReaderOutOfDataErr;
        } else {
            const v = self.payload[self.off];
            self.off += 1;
            return v;
        }
    }

    pub fn readBytes(self: *Self, n: usize) BufferError![]const u8 {
        if (self.off + n > self.payload.len) {
            return BufferError.ReaderOutOfDataErr;
        } else {
            const sl = self.payload[self.off .. self.off + n];
            self.off += n;
            return sl;
        }
    }

    pub fn readU32(self: *Self) BufferError!u32 {
        if (self.off + 4 > self.payload.len) {
            return BufferError.ReaderOutOfDataErr;
        } else {
            const v = std.mem.bytesToValue(u32, self.payload[self.off .. self.off + 4]);
            self.off += 4;
            return std.mem.toNative(u32, v, .big);
        }
    }

    pub fn readU32LenString(self: *Self) BufferError![]const u8 {
        const len = try self.readU32();
        return try self.readBytes(len);
    }
};
```

Using `BufferReader`, we can now progressively read bytes from a packet as follows:

```zig
var reader = BufferReader.init(raw_packet_bytes);
const msg_id = try reader.readU8();
const algorithms = try reader.readU32LenString();   // get that comma separated list of algorithms
```

Much simpler.

In my SSH client, the real code to read and print the `SSH_MSG_KEXINIT` packet looks like this:

```zig
const cookie = try rdr.readBytes(16);
TRACEDUMP(.Debug, "cookie", .{}, cookie);

const listnames = [_][]const u8{
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
};

for (listnames) |listname| {
    TRACE(.Debug, "{s}: ", .{listname});
    var iter = util.NameListTokenizer.init(try rdr.readU32LenString());
    while (iter.next()) |name| {
        TRACE(.Debug, "  '{s}' ", .{name});
    }
}

const first_kex_packet_follows = try rdr.readBoolean();
TRACE(.Debug, "first_kex_packet_follows = {any}\n", .{first_kex_packet_follows});
_ = try rdr.readU32(); // reserved, ignore
```

To construct packets, there is a `BufferWriter`. It works similarly, but with one extra trick. As we saw earlier, SSH packets have a header at the beginning with the `packet_length`. However, it would be easier if we could construct a packet then write the header at the end, as we won't always know what the length will be before starting.

With `BufferWriter`, we provide a `backingbuf` slice to write data into, but we may also reserve space at the front of the packet for a future header to be written. In `init()`, the `pre_payload_len` (size of the SSH header) is skipped leaving a gap before writing data. Each write function calls `updateUnderlying()` which ensures that `.payload` always holds the slice of all data written so far.

```zig
pub const BufferWriter = struct {
    const Self = @This();
    payload_buf: []u8,
    payload: []u8,
    off: usize = 0,
    pre_payload_len: usize = 0,

    pub fn init(backingbuf: []u8, pre_payload_len: usize) Self {
        var s = Self{
            .off = 0,
            .payload_buf = backingbuf,
            .pre_payload_len = pre_payload_len,
            .payload = &.{},
        };
        _ = s.skip(pre_payload_len) catch 0;
        return s;
    }

    pub fn skip(self: *Self, n: usize) BufferError!void {
        if (self.off + n > self.payload_buf.len) {
            return BufferError.WriterOutOfDataErr;
        } else {
            self.off += n;
            self.updateUnderlying();
        }
    }

    pub fn updateUnderlying(self: *Self) void {
        self.payload = self.payload_buf[0..self.off];
    }

    pub fn writeU8(self: *Self, v: u8) BufferError!void {
        if (self.off + 1 > self.payload_buf.len) {
            return BufferError.WriterOutOfDataErr;
        } else {
            self.payload_buf[self.off] = v;
            self.off += 1;
            self.updateUnderlying();
        }
    }

    pub fn writeBytes(self: *Self, v: []const u8) BufferError!void {
        if (self.off + v.len > self.payload_buf.len) {
            return BufferError.WriterOutOfDataErr;
        } else {
            @memcpy(self.payload_buf[self.off .. self.off + v.len], v);
            self.off += v.len;
            self.updateUnderlying();
        }
    }

```

Now, constructing a packet is also straightforward:

```
var writer = BufferWriter.init(backingbuf, sizeof_header);
try writer.writeU8(SSH_MSG_KEXINIT);
try writer.writeBytes(cookie);
...
// Before sending, write header bytes into writer.payload_buf[0..sizeof_header]

```

## Establishing security

Now that we can build and parse packets, let's look at how SSH establishes a secure connection.

SSH is a flexible protocol supporting a whole range of different algorithms and key exchange mechanisms. We're going to look at just one, ECDH, and see how it negotiates a secure link.

Broadly speaking, there are two types of cryptography we need to be aware of - public key and symmetric. Here's a quick overview if this is new to you.

Symmetric cryptography uses a single key to both encrypt and decrypt. [ROT-13](https://en.wikipedia.org/wiki/ROT13), although trivial to break is a classic example. Some symmetric algorithms do have different keys for encryption and decryption, but there is always a simple transformation between the two keys such that knowing one means you know both. Modern algorithms such as [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) are very hard to break without the key, but still require both parties to have access to the single secret key. Symmetric encryption is very efficient on modern processors. Even tiny microcontrollers often have dedicated hardware devoted to it.

Public-key cryptography splits the key into two parts, a key pair. The secret/private key is never revealed, while the public key part can be freely shared. The two parts are mathematically linked, but cannot be easily derived from each other. The two most popular systems for public key cryptography are RSA and ECC. In RSA, the difficulty of deriving one key from another comes from the problem of factoring large primes, whereas with ECC it's assumed that finding the discrete logarithm of an elliptic curve element with respect to a known point is infeasible.

In a parallel with symmetric cryptography, a message encrypted with the public key can only be decrypted using the private key. This allows anyone with the freely shared public key to send a hidden message to the holder of the private key.

However, public-key cryptography allows another trick. If the holder of the private key encrypts a message using the private key, it can be decrypted by anyone with the public key, proving that the message must have come from the private key holder. This process is called signing and checking a signature is called verification.

To sign a message, the private key holder creates a [hash](https://en.wikipedia.org/wiki/Cryptographic_hash_function) of the message then signs the hash using their private key. Anyone with the public key can then verify the authenticity of the signature ensuring it originated from the private key holder.

Unlike symmetric cryptography, public key algorithms are relatively slow and computationally expensive. Due to this, SSH (and other protocols such as TLS) use public key cryptography to exchange a set of symmetric keys, then use just those for the remainder of the session. This process is called "key exchange" ("kex" in the SSH RFCs).

SSH supports several different key exchange protocols, but let's look at how SSH uses just one - [ECDH](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#General_overview). In Elliptic Curve Diffie–Hellman, two parties can agree a shared secret over a public channel. To do this, each side generates a keypair and some publicly shared data. By sharing their public keys and mathematically combining with their private keys, each side can arrive at a shared secret which only they know.

(For an enjoyable book on the people and history read Steven Levy's [Crypto](https://www.stevenlevy.com/crypto))

Here are the steps SSH uses to agree a shared secret using ECDH. At each step, the data transferred is given a name and recorded for later steps.

 - Client sends a client identification string ending CR LF (`V_C`)
 - Server sends a server identification string ending CR LF (`V_S`)
 - Client sends `SSH_MSG_KEXINIT` listing which algorithms they prefer (`I_C`)
 - Server sends `SSH_MSG_KEXINIT` listing which algorithms they prefer (`I_S`)
 - Client generates ephemeral keys
 - Client sends `SSH_MSG_KEX_ECDH_INIT` with their ephemeral public key (`Q_C`)
 - Server generates ephemeral keys
 - Server generates the key exchange hash `H` = HASH(`V_C`+`V_S`+`I_C`+`I_S`+`K_S`+`Q_C`+`Q_S`)
 - Server sends `SSH_MSG_KEX_ECDH_REPLY` with their ephemeral public key (`Q_S`), their host key (`K_S`) and signs the key exchange hash with their host private host key
 - Both sides use ECDH to generate the shared secret `K` from `Q_C` and `Q_S` - which only they could know
 - Client generates the key exchange hash `H` = HASH(`V_C`+`V_S`+`I_C`+`I_S`+`K_S`+`Q_C`+`Q_S`) and validates the signed key exchange hash against `K_S`. It now knows it's talking to the server it intends to
 - Both sides now have the key exchange hash `H` (public) and shared secret `K` (private)

Phew.

In just a few messages, [all of the important pieces of information were shared](https://datatracker.ietf.org/doc/html/rfc4253#section-7.2).

 - The client knows it's talking to the real server (as server signed something using its host key)
 - Both client and server have calculated `H` (public) and `K` (secret to them both)

Now, both sides generate a set of symmetric keys which only they could know. 6 pieces of key data are generated, 3 for each direction (client to server/server to client). A key, an IV and a MAC key.

Both sides then send an `SSH_MSG_NEWKEYS` message to confirm that they want to switch to encrypted communications - and the link goes secure.

## Secure messages

Now that both sides have agreed a set of symmetric keys, all messages are encrypted.

Each message is generated as before but is encrypted with AES (or other chosen cipher). AES requires 2 of the piece of key data generated earlier, a key and IV. The IV gives the initial state of the encryption algorithm and the key is used to encrypt/decrypt. AES is SSH is always used in one of the cipher-block-chaining modes where previous data is fed back through the encryption algorithm's next step to ensure that a single block cannot be decrypted without knowing everything which came before.

Encrypting messages keeps them secure from prying eyes, but does nothing to prevent a determined attacker from inserting garbage into the stream. For this reason a MAC (Message Authentication Code) is appended to each message. Both client and server maintain a count of how many messages they have sent. This sequence number and the message data are combined and hashed to generate a MAC - proving that this message is the next in sequence and came from a trusted source.

Revisiting [RFC-4253 The Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253#section-6)

	Each packet is in the following format:
	
	      uint32    packet_length
	      byte      padding_length
	      byte[n1]  payload; n1 = packet_length - padding_length - 1
	      byte[n2]  random padding; n2 = padding_length
	      byte[m]   mac (Message Authentication Code - MAC); m = mac_length

Each message now has a MAC appended to the end. The size of the MAC depends on the algorithm agreed upon in `SSH_MSG_KEXINIT`.

When reading encrypted messages, the receiver must do a bit more work than before. Firstly, the `packet_length` is encrypted - so just the first AES block must be read and decrypted to determine how much more to read and decrypt. AES has a fixed block size (16 bytes) and doesn't allow decyption of less than a single block. Now, we can make sense of the `padding` - it's there so that every packet is an exact number of AES blocks.

Once the packet has been decrypted, the receiver can generate what they think the MAC should be and compare with what was received. If the MACs match then this message can be trusted.

## Summary

Hopefully this article has dispelled some of the mystery around how SSH establishes a secure link and time you run `ssh -vvv user@host` you'll know what's being talked about.

For more detail and runnable code, check out https://github.com/ringtailsoftware/misshod

https://mastodon.me.uk/@tobyjaffey





