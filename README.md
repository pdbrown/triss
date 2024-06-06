# Triss

**TRI**vial **S**ecret **S**haring with authentication, support for M-of-N
splits, and paper backups.

Triss is a command line tool that takes input data (the "secret") and splits it
into multiple shares such that no single share can recover the secret. In
reverse, it combines shares to recover the secret, using message authentication
codes (MACs) to ensure the recovered secret is identical to the original. Triss
supports _N-of-N_ and _M-of-N_ splits, `2-of-2` or `3-of-5` for example.
Formally:

> Split a secret into `N` shares, such that every subset of `M` shares contains
the information needed to reconstruct the secret. `M >= 2` and `N >= M`. No
subset smaller than `M` reveals any information about the secret, but see
[cryptography](#cryptography) below.

Triss supports two output modes: `DATA` and `QRCODE`. In `DATA` mode, it writes
shares as plain binary files without any special encoding. In `QRCODE` mode, it
generates QR codes as PNG images that can be printed onto paper.


## Rationale

Use `triss` to make encrypted backups without having to remember an encryption
key or password. Trivial secret sharing is handy when you want high confidence
your data will be recoverable far into the future: decryption is a
straightforward XOR of the shares, [see below](#how-does-it-work), and easy to
re-implement from scratch should this software disappear or become unusable some
day.

Say you split a secret into `N = 3` shares, requiring `M = 2` shares to recover
it. Give one share to your best friend, another to your lawyer, and keep the
third one. You trust your lawyer not to collude with your friend, and if you
ever need access to your data, you can recover it as long as you can get 2 of
the 3 shares. When you die, your friend and lawyer can discover what you've been
hiding all these years.


## How does it work?

[Trivial secret
sharing](https://en.wikipedia.org/wiki/Secret_sharing#Trivial_secret_sharing) is
quite simple and works by combining the secret with a random number using the
[exclusive or](https://en.wikipedia.org/wiki/Exclusive_or) (XOR) operation. This
is the same idea as a [stream
cipher](https://en.wikipedia.org/wiki/Stream_cipher) or [one-time
pad](https://en.wikipedia.org/wiki/One-time_pad), depending on the source of the
[randomness](#randomness).

For a 2-of-2 split:
- Represent your secret as a binary number `P`.
- Generate a random number `K` of the same length as `P`.
- Combine `P` and `K` to make `C = P xor K`.
- Distribute `C` and `K` as the 2 shares of the secret.
- Recover the secret by combining them: `C xor K = P`.

Proof:
```
Given P                      your Plaintext data (the "secret")
Generate K, |K| = |P|        a random Key, same length as P
C       = P xor K            produce Ciphertext by encrypting Plaintext with Key
C xor K = (P xor K) xor K    xor Key on both sides
C xor K = P xor (K xor K)    xor is associative
C xor K = P xor 0            simplify: K xor K = 0
C xor K = P                  simplify: P xor 0 = P. Recover Plaintext data.
```

For `N of N` splits with more shares, generate more keys `K2`, `K3`, etc and XOR
them all into `P` to make `C`. The shares are `C` and all keys `K`, `K2`, `K3`,
etc.

For `M of N` splits where `M < N`, make a separate `M of M` split for each
of the $\binom{N}{M}$ subsets.


## Installation

### Prerequisites
Triss is a python program that requires python `3.11` or newer. There are no
additional prerequisites for `DATA` file mode, but the `QRCODE` mode depends on
external programs [`qrencode`](https://github.com/fukuchi/libqrencode) for
splitting/encoding and [`zbarimg`](https://github.com/mchehab/zbar) for
combining/decoding.

```
| Dependency  | Minimum Version |   Released |
|-------------+-----------------+------------|
| python      |            3.11 | 2022-10-24 |
| libqrencode |           4.1.1 | 2020-09-28 |
| zbarimg     |          0.23.1 | 2020-04-20 |
```

Note the minimum version of `zbarimg` is a hard requirement, because support for
binary data was added in `0.23.1`. Older versions of `qrencode` may work, but
haven't been tested.

Python is available at https://www.python.org/downloads/.

#### Debian / Ubuntu
```bash
sudo apt install qrencode zbar-tools
```

#### Redhat / Fedora
```bash
sudo dnf install qrencode zbar
```

#### macOS
```bash
brew install qrencode zbar
```

#### Windows

##### qrencode
See https://fukuchi.org/works/qrencode/ or
https://github.com/fukuchi/libqrencode.

##### zbarimg
Either download from https://linuxtv.org/downloads/zbar/binaries/ or to build
from source, see https://github.com/mchehab/zbar.


### Dist Package
The following steps usually happen in a python virtual environment. Set one up
like this:
```bash
$(command -v python3 || command -v python) -m venv venv
source venv/bin/activate
```

Then either install `triss` from [pypi](https://pypi.org/) directly without
verification:
```bash
pip install triss
```

Or download, verify, and install:
```bash
# Download
pip download triss

# Import my gpg key
gpg --keyserver keyserver.ubuntu.com --recv-keys 219E9F62C560C55D2AFA44AEE970EC6EC2E57448

# Download the SHA256SUMS and SHA256SUMS.asc
wget https://github.com/pdbrown/triss/releases/download/v1.0/SHA256SUMS
wget https://github.com/pdbrown/triss/releases/download/v1.0/SHA256SUMS.asc

# Verify the package
gpg --verify SHA256SUMS.asc
sha256sum --check SHA256SUMS

# Install
pip install triss-1.0-py3-none-any.whl
```


## Usage

The dist package installs the `triss` wrapper script into the PATH of your
venv.

### Split secret
```
triss split [-h] [-m M] [-i IN_FILE] [-c {DATA,QRCODE}] [-t SECRET_NAME] [-k] N DIR

positional arguments:
  N                 number of shares
  DIR               destination directory path

options:
  -h, --help        show this help message and exit
  -m M              number of required shares for M-of-N split
  -i IN_FILE        path to input file, read from stdin if omitted
  -c {DATA,QRCODE}  output file format, defaults to DATA
  -t SECRET_NAME    name of secret to include on QRCODE images
  -k                skip combine check after splitting
```

### Recover secret
```
usage: triss combine [-h] [-c {DATA,QRCODE}] [-o OUT_FILE] [--DANGER-allow-invalid] DIR [DIR ...]

positional arguments:
  DIR                   one or more directories containing input files to combine

options:
  -h, --help            show this help message and exit
  -c {DATA,QRCODE}      input file format, will guess if omitted
  -o OUT_FILE           write secret to output file, or stdout if omitted
  --DANGER-allow-invalid
                        Don't stop decoding on message authentication error. WARNING! There
                        is no guarantee the decoded output matches the original input.
```


## Examples

Prepare a demo secret for the following examples.
```bash
echo "Hello there." > demosecret.txt
```

### Split secret in DATA mode

Shares of the secret are stored in plain binary files. This handy when the
secret is large and you don't care about making paper copies.

```bash
# Make 2-of-4 split
triss split -i demosecret.txt -m 2 4 data-shares
```

### Split secret in QRCODE mode

Shares of the secret are produced the same way as in DATA mode, then encoded as
QR codes. This allows you to make paper copies, but can be slow and cumbersome
for large inputs. Each QR code stores up to 1273 bytes, and is generated with
error correction set to "High", so is scannable as long as at least 70% of the
original image is available (the finder pattern must be intact regardless).

```bash
# Make a 2-of-4 split in QRCODE mode
triss split -i demosecret.txt -c QRCODE -t mysecret -m 2 4 qr-shares
```

### Recover secret

```bash
# Recover from any 2 shares
triss combine -o output.txt data-shares/share-0 data-shares/share-3

# Recover from (photos of) QR codes
triss combine -o output_qr.txt qr-shares/share-1 qr-shares/share-2
```

### Distribute shares

Each share is put into its own subdirectory and consists of _multiple parts_.
Make sure you keep parts of a share together and distribute complete shares with
all their parts. If any part is missing, the share is useless.

For example: One of the 3 shares of a 2-of-3 split produced with
```bash
triss split -i input.txt -c DATA -m 2 3 shares
```

is given to each of 3 participants A, B, and C. Each participant must keep all 4
parts of their share.

```
Participant A gets all of:
share-0
├── share-0_part-1_of_4.dat
├── share-0_part-2_of_4.dat
├── share-0_part-3_of_4.dat
└── share-0_part-4_of_4.dat

Participant B gets all of:
share-1
├── share-1_part-1_of_4.dat
├── share-1_part-2_of_4.dat
├── share-1_part-3_of_4.dat
└── share-1_part-4_of_4.dat

Participant C gets all of:
share-2
├── share-2_part-1_of_4.dat
├── share-2_part-2_of_4.dat
├── share-2_part-3_of_4.dat
└── share-2_part-4_of_4.dat
```


## Development

### Install From Source
```bash
git clone https://github.com/pdbrown/triss && cd triss
$(command -v python3 || command -v python) -m venv venv
source venv/bin/activate
make dev
```

### Test
```bash
make test
make stress
```

### Build
```bash
# Build dist package.
make build

# Or build and sign it. The sign recipe invokes gpg and passes extra GPG_OPTS
# you can set in the environment.
make sign
```

Note that building runs `pip install` in non-editable mode, so you'd need to
re-run `make dev` (or `pip install --editable '.[qrcode,test]'`) to reset the
dev environment.

#### Container
```bash
# Build a docker image that contains both signed triss and zbarimg
make docker
# or if you prefer podman, do
make docker DOCKER=podman

# The container entrypoint is the triss cli, and the image contains an /app
# directory, so you can do:
echo "Another secret." > mysecret.txt
docker run --rm -v .:/app triss:latest \
    split -i /app/mysecret.txt -c QRCODE -m 2 3 /app/qrshares

# Find shares here:
find ./qrshares
```

You can also run the container with `systemd-nspawn`. After building the image,
do:
```bash
VERSION=$(awk -F\" '/^version/ { print $2 }' pyproject.toml)
docker create --name triss_$VERSION triss:$VERSION
docker export -o triss_${VERSION}.tar triss_${VERSION}
mkdir rootfs
tar xf triss_${VERSION}.tar -C rootfs

echo "So many secrets." > rootfs/app/input.dat
sudo systemd-nspawn --quiet --directory rootfs \
    /venv/bin/triss split -i /app/input.dat -c QRCODE -m 2 3 /app/qrshares

# And find result in
find rootfs/app/qrshares
```


## Details

### Motivation

There are many other tools that do secret sharing, so why build `triss`?

- https://iancoleman.io/shamir/
- https://github.com/jesseduffield/horcrux
- http://point-at-infinity.org/ssss/
- https://github.com/cyphar/paperback
- ... and more

These other tools implement [Shamir's Secret
Sharing](https://en.wikipedia.org/wiki/Shamir's_secret_sharing) or similar. A
major advantage of Shamir's method is that the size of each share is linear in
the size of the secret, whereas trivial secret shares grow as
`O($\binom{N}{M}$)` because they include a fragment of the secret from every
subset of size `M`.

While Shamir's secret sharing has its advantages, it's also harder to
understand, and so it's harder to verify an implementation is correct. The
system should also produce authenticated messages, since secret sharing is
malleable: a flipped bit in the ciphertext (any of the shares) leads to a
flipped bit in the decoded plaintext. The system should support digital and
paper output formats.

So `triss`:
- Is an implementation of trivial secret sharing: easy to use, understand, and
  reproduce.
- Tags shares of secrets with message authentication codes.
- Produces either data file or printable QR code outputs.


### Cryptography

#### Randomness

Secret sharing schemes are often described as having [information-theoretic
security](https://en.wikipedia.org/wiki/Information-theoretic_security) aka
perfect secrecy, because an attacker with `M-1` shares knows no more about the
secret than someone without any shares at all. That is, all secrets are equally
likely, and an attacker is left guessing at random.

This property of perfect secrecy depends on the key being _truly_ random. The
key here is the `K` [above](#how-does-it-work) (or the set of randomly chosen
coefficients of a polynomial in the case of [Shamir's
method](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing#Mathematical_formulation)).

In practice, however, these keys are pseudorandom, since they're generated by
your operating system's [cryptographically secure pseudorandom number generator
(CSPRNG)](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).
Instead of an infinite number of possible random key streams (sequences of
random 1s and 0s) there are "only" as many as many pseudorandom keystreams as
can be enumerated by the internal states of the CSPRNG. For example, recent
versions of
[linux](https://github.com/torvalds/linux/blob/v5.18/drivers/char/random.c) use
a [ChaCha](https://www.zx2c4.com/projects/linux-rng-5.17-5.18/) based CSPRNG
with a 256 bit key size. Thus while there are no less than `2^256` different key
streams, there are not infinitely many.

So given a `triss` share `C`, if an attacker attempts to brute force a key `K` to
recover the plaintext with `P = C xor K`, they can narrow their search from the
space of all possible keystreams to that of the no less than `2^256` keystreams
generated by the CSPRNG.

While no longer perfect secrecy, this degree of security is good enough,
computationally infeasible to break, and the same as that of other modern
cryptography provided the CSPRNG is not broken.

##### Footnotes
Triss uses python's `secrets.token_bytes` method to generate keys. That calls
`os.urandom`, which uses the `getrandom(2)` system call in blocking mode on
linux (kernel version `>= 3.17`).

On linux, see also `man 7 random`, `man 2 getrandom`, and the legacy random
device interface manual at `man 4 random`.


#### Authentication

##### Malleablility

A problem with trivial secret sharing is that it does nothing to authenticate
messages. An attacker or dishonest participant can corrupt their share such that
the combined result no longer reproduces the original input. Even worse, trivial
secret sharing is
[malleable](https://en.wikipedia.org/wiki/Malleability_(cryptography)), which
means the attacker cause the reconstructed input to be altered in a predictable
way. Flipping any bit of an encrypted share causes the corresponding bit of the
combined result to be flipped too. This can be disastrous if the secret is an
instruction. Say a dishonest participant knows a message is either "attack" or
"defend". They can corrupt their share such that the combined result is always
the opposite of the original input, without knowing what the original input was.

```python
# Demonstrate 2-of-2 trivial secret split malleability
import secrets
def xor(xs, ys):
    return bytes(x ^ y for x, y in zip(xs, ys))

# Split secret
plaintext = b"attack"
share_1 = secrets.token_bytes(len(plaintext))  # give to honest participant
share_2 = xor(plaintext, share_1)              # give to dishonest participant

# Corrupt share
corruption = xor(b"attack", b"defend")
share_2_corrupted = xor(share_2, corruption)

# Attept recovery of secret
xor(share_1, share_2_corrupted)
# => b"defend"
```

And if the original input had been `b"defend"`, the recovered data would be
`b"attack"` instead. This same attack is possible on executable programs with
well-known header formats.

##### Message authentication codes

Triss uses HMAC-SHA-384 hash-based message authentication codes (MACs) to
validate the authenticity of shares in an [encrypt then
mac](https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_(EtM))
fashion as follows.

For each share of the split secret:
- Given the (split) data `Si` for `i`th share,
- Generate a 384 bit key `Ki` and
- Compute a MACi = HMAC-SHA-384(Si, Ki)

Then concatenate the MACs of all shares, and include with each share the MACs of
all shares. Also give each share its own key `Ki`, but no keys of the MACs of
any other share. When combining, reveal data and keys of all shares, recompute
MACs of each share, and verify they match the original MACs distributed with
your share.

It may seem unnecessary to use HMACs: wouldn't simpler (secure) hash functions,
say plain SHA384, suffice? While a plain hash digest proves authenticity, it
also allows an attacker, another participant in this case, to guess your share
by brute force. They enumerate and test all bit strings until they find a
matching digest and thus your share. This is very easy for short secrets, say a
4 digit PIN number. By using a _keyed_ hash function like HMAC, the attacker
must also guess your (384 bit) key which is computationally infeasible.


#### Encryption vs Trivial Secret Sharing

Here's a different way to implement 2-of-2 trivial secret sharing using standard
symmetric encryption:

To split the secret:
- Generate a random key `k`, at least 256 bits long.
- Encrypt the plaintext with the key to produce ciphertext `c`.
- Distribute `k` and `c` as the 2 shares.

To combine the shares:
- Decrypt `c` with `k` to recover the input.

To extend to 3-of-3 secret sharing, encrypt the first key `k` with another key
`k2` to produce ciphertext `c2`, and distribute `k2`, `c2`, and the original
input's ciphertext `c`.

Depending on the choice of algorithm, the security properties of `triss` are
similar to those of symmetric encryption. In particular, `triss` on linux is
similar to the
[ChaCha20](https://datatracker.ietf.org/doc/html/rfc8439#section-2.4) stream
cipher, which generates a pseudorandom keystream from a 256 bit key and other
fixed size input, then XORs that stream with the plaintext to produce the cipher
text. On linux (as of kernel 4.8), the CSPRNG is based on the part of ChaCha
that generates the keystream. It has an unguessable, hidden, internal state of
at least 256 bits, which is analagous to the ChaCha20 key.

So if you split (encrypt) your secret with ChaCha20, you keep the ciphertext and
the 256 bit key as the two shares. If you split your secret with `triss`, you
keep the ciphertext and the entire keystream (CSPRNG output) used to encrypt it,
which is as long as the ciphertext.

The advantage of ChaCha20 is you typically need less total storage to keep the 2
shares: `|C| + 256` vs `2|C|` bits. The advantage of `triss` is that decryption
is simpler: you don't need to know how to re-generate the keystream from the
key, because you saved it in its entirety.


## Algorithm

### Data layout
Largest QR code (size/version "40") can hold 1273 bytes of data in maximum
error correction mode. Reserve first k bytes for header, rest for data.
If output is to a .dat files instead, each fragment is packed into a single
segment of unlimited size (see also 'Detailed steps' below).

| Header (20 bytes total)                                         |
| Version | Flags   | Dataset ID | Fragment index | Segment index |
| 2 byte  | 4 bytes | 4 bytes    | 4 bytes        | 4 bytes       |

| Header          | Data                                                   |
| Header checksum | Uncompressed or GZipped data                           |
| 2 bytes         | 0 - 1253 bytes for QR code, else .dat file 0 - n bytes |


### Split input into multiple shares
Input data is split using a "trivial secret sharing" algorithm.
See https://en.wikipedia.org/wiki/Secret_sharing#Trivial_secret_sharing
Input data is compressed with gzip, split into fragments by XOR with
one-time pads, and broken into segments, each of which fits into a QR code.

**Detailed steps**
- Compress input with gzip.
- Let n be the number of shares needed to reconstruct the input.
- Generate n-1 one-time pads (otp_1 through otp_(n-1)). A one-time pad is a
  cryptographically secure (i.e. unguessable) random string of bits of same
  length as the original data (length of the compressed input in this case).
- Return the result of XOR(compressed_data, otp_1, ..., otp_(n-1)) as the
  first fragment and the one-time pads as remaining fragments for a total of
  n fragments.
- Break each fragment into segments:
  - If output is QR code format: break each fragment into 1266 byte
    "segments". A segment fits into a QR code (1273 bytes max = 9 bytes
    header + up to 1264 bytes data).
  - If output is .dat file format, leave the fragment whole, as a single
    segment.
For each segment:
- Construct 9 byte header:
  - Field 1 holds the version of this program used to write the file.
  - Field 2 holds a set of bit flags, e.g. whether data is compressed with
    gzip.
  - Field 3 is the "Dataset ID", which identifies a set of fragments
    which, when combined, can reproduce the original input.
  - Fields 4 and 5 identify the fragment (by 0-based index) and specify total
    number of fragments, e.g.:
      Field 4, share index: 0
      Field 5, num shares:  3
    means this is the first of 3 total shares.
  - Fields 6 and 7 identify the segment (by 0-based index) and total number
    of segments.
      Field 6, segment index: 1
      Field 7, num segment:   2
    means this is the second (last) of 2 total segments.
  - Fields 8 and 9 contain a checksum of all preceding header bytes.
- Build the payload by concatenating header and data segment.
- Write payload:
  - To a QR code as PNG file, or
  - As a binary .dat file.


### Merge shares to recover original data
Given all output files obtained by running the split algorithm above:
- Decode them:
  - Decode QR codes into byte arrays, or
  - Read byte arrays from .dat files.
- Parse headers
  - Validate their checksums.
  - Assert their version fields match the version of this program.
- Group segments by dataset id then fragment index.
- Assert all segments of all fragments are available.
- Concatenate each segment in order by index to obtain the fragment.
- Combine the fragments with XOR to obtain the compressed input.
- Decompress the input to obtain the original plaintext data.


### M-of-N shares
So far, data was split into N shares, each of which is needed to reconstruct
the original. To split into M-of-N shares, so that data can be recovered with
any M of N total shares, do an M-way split for each subset (size M) of N
shares that should have access to the data: N choose M for a full M-of-N
split.
E.g. for 2-of-3 sharing: make 3 separate 2-of-2 splits, using a different
dataset ID for each, say A, B, and C.
Then choose pairs of fragments from each set (assuming 1 segment for this
example), and bundle those into 3 shares, any 2 of which are enough to
recover the original:

share 1:  A1, B1
share 2:  A2,     C1
share 3:      B2, C2

Or for 2-of-4 splits, make 6 2-of-2 splits and arrange as follows:
share 1:  A1, B1, C1
share 2:  A2,         D1, E1
share 3:      B2,     D2,     F1
share 4:          C2,     E2, F2

This scheme becomes unwieldy for larger splits. For better M-of-N share
algorithms consider:
https://en.wikipedia.org/wiki/Secret_sharing#Efficient_secret_sharing


See also https://en.wikipedia.org/wiki/Secret_sharing#Trivial_secret_sharing


### MAC data layout
MAC data layout for 3-of-5 example.
```
For aset A:
  share 0: A1_key, A1_MAC, A2_MAC, A3_MAC, A1_MAC, A2_MAC, A3_MAC
  share 1: A2_key, A1_MAC, A2_MAC, A3_MAC, A1_MAC, A2_MAC, A3_MAC
  share 2: A3_key, A1_MAC, A2_MAC, A3_MAC, A1_MAC, A2_MAC, A3_MAC
                   ^-- segment 0           ^-- segment 1

Simplest Example: 2-of-2 split
1 segment segment_id=0
1 authorized set aset_id=0
2 fragments: A1 and A2

share 0:
  segment 0: A1
share 1:
  segment 0: A2

Participant 0 gets share 0 which includes:
- A1: segment_id=0, fragment_id=0
- MAC key_A1 (aset_id=0, fragment_id=0, segment_id=0)
- MAC digest of (key_A1, A1)
- MAC digest of (key_A2, A2)

Participant 1 gets share 1 which includes:
- A2: segment_id=0, fragment_id=1
- MAC key_A2 (aset_id=0, fragment_id=1, segment_id=0)
- MAC digest of (key_A1, A1)
- MAC digest of (key_A2, A2)
```







## License

GNU General Public License v3.0 or later

See [COPYING](COPYING) to see the full text.
