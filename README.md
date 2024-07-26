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

See also [implementation notes](#implementation) for details below.


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
echo "Hello there." > secret.txt
```

### Split secret in DATA mode

Shares of the secret are stored in plain binary files. This handy when the
secret is large and you don't care about making paper copies.

```bash
# Make 2-of-4 split
triss split -i secret.txt -m 2 4 data-shares
```

### Split secret in QRCODE mode

Shares of the secret are produced the same way as in DATA mode, then encoded as
QR codes. This allows you to make paper copies, but can be slow and cumbersome
for large inputs. Each QR code stores up to 1273 bytes, and is generated with
error correction set to "High", so is scannable as long as at least 70% of the
original image is available (the finder pattern must be intact regardless).

```bash
# Make a 2-of-4 split in QRCODE mode
triss split -i secret.txt -c QRCODE -t mysecret -m 2 4 qr-shares
```

### Recover secret

```bash
# Recover from any 2 shares
triss combine -o output.txt data-shares/share-0 data-shares/share-3

# Recover from original QR code image files, or photos of printed copies.
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
```

The following steps must be done in a python virtual environment, or else the
Makefile will complain. Set one up like this:

```bash
$(command -v python3 || command -v python) -m venv venv
source venv/bin/activate
```

Finally, enable development mode. This creates an "editable install" in the
venv.

```bash
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

Note that `make build` and `make sign` disable development mode (by running `pip
install` in non-editable mode), so you'd need to re-run `make dev` to reenable
it for subsequent development.

#### Container
```bash
# Build a docker image that contains both signed triss and zbarimg packages
make docker
# or if you prefer podman, do
make docker DOCKER=podman

# The container entrypoint is the triss cli, and the image contains an /app
# directory, so you can do:
echo "General Kenobi." > secret.txt
docker run --rm -v .:/app triss:latest \
    split -i /app/secret.txt -c QRCODE -m 2 3 /app/shares

# And find the shares here:
find ./shares
```

You can also run the container with `systemd-nspawn`. After building the image,
do:
```bash
VERSION=$(awk -F\" '/^version/ { print $2 }' pyproject.toml)
docker create --name triss_$VERSION triss:$VERSION
docker export -o triss_${VERSION}.tar triss_${VERSION}
mkdir rootfs
tar xf triss_${VERSION}.tar -C rootfs

echo "You are a bold one." > rootfs/app/input.dat
sudo systemd-nspawn --quiet --directory rootfs \
    /venv/bin/triss split -i /app/input.dat -c QRCODE -m 2 3 /app/shares

# And find the shares here:
find rootfs/app/shares
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
subset of `N` elements of size `M`.

While Shamir's secret sharing has its advantages, it's also harder to
understand, and so it's harder to verify an implementation is correct.

The secret sharing system should also produce authenticated shares, since secret
sharing is malleable: a flipped bit in the ciphertext (any of the shares) leads
to a flipped bit in the decoded plaintext. The system should support digital and
paper output formats.

So `triss`:
- Is an implementation of trivial secret sharing: easy to use, understand, and
  reproduce.
- Tags shares of secrets with message authentication codes.
- Produces either data file or printable QR code output.


### Cryptography

#### Randomness

Secret sharing schemes are often described as having [information-theoretic
security](https://en.wikipedia.org/wiki/Information-theoretic_security) aka
perfect secrecy, because an attacker with `M-1` shares knows no more about the
secret than someone no shares at all. That is, even with knowledge of up to
`M-1` of the shares, all secrets remain equally likely, and an attacker would
still be left guessing at random.

This property of perfect secrecy depends on the key being _truly_ random. The
key here is the `K` [above](#how-does-it-work) (or would be the set of randomly
chosen coefficients of a polynomial in the case of [Shamir's
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
computationally infeasible to break, and on par with modern cryptography.

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
the combined result no longer matches the original input. Even worse, trivial
secret sharing is
[malleable](https://en.wikipedia.org/wiki/Malleability_(cryptography)), which
means an attacker can alter the reconstructed output in a predictable way.
Flipping any bit of an encrypted share causes the corresponding bit of the
combined result to be flipped too. This can be disastrous if the secret is an
instruction (or a computer program in a predictable format). Say a dishonest
participant knows a message is either "attack" or "defend". They can corrupt
their share such that the combined result is always the opposite of the original
input, without knowing the original input in the first place.

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

And if the original input had been `b"defend"`, the recovered data would become
`b"attack"` instead.

##### Message authentication codes

Triss uses HMAC-SHA-384 hash-based message authentication codes (MACs) to
validate the authenticity of shares in an [encrypt then
mac](https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_(EtM))
fashion as follows.

For each share `i` of the split (encrypted) secret:
- Generate a random 384 bit key `Ki` and
- Given its split (encrypted) data `Si`,
- Compute a `MACi = HMAC-SHA-384(Si, Ki)`

Then include with each share the MACs of all shares. Also give each share its
own key `Ki`, but no keys of any other share. When combining, reveal data and
keys of all shares, recompute MACs of each share, and verify they match the
original MACs distributed with your share.

It may seem unnecessary to use HMACs: wouldn't plain (secure) hash functions,
say SHA384, suffice? While a hash digest proves authenticity, it also allows an
attacker, another participant in this case, to guess your share by brute force.
They enumerate and test all bit strings until they find a matching digest and
thus your share. This is quite easy for a short secret, say a password or PIN
number. By using a _keyed_ hash function like HMAC, the attacker must also guess
your (384 bit) key which is computationally infeasible.


#### Encryption vs Trivial Secret Sharing

Another way to do 2-of-2 trivial secret sharing is to use standard symmetric
encryption (ChaCha20 or AES256 for example):

To split the secret:
- Generate a random key `k`, at least 256 bits long.
- Encrypt the plaintext with `k` to produce ciphertext `c`.
- Distribute `k` and `c` as the 2 shares.

To combine the shares:
- Decrypt `c` with `k` to recover the input.

To extend to 3-of-3 secret sharing, encrypt the first key `k` with another key
`k2` to produce ciphertext `c2`, and distribute `k2`, `c2`, and the original
input's ciphertext `c`.

##### Advantages of symmetric encryption

Possible space savings. With `triss`, each share is the same size as the
original input. With symmetric encryption only the ciphertext `c` is, while the
other shares have a fixed size: the `k`s, typically 256-512 bits depending on
the chosen key size.

##### Advantages of `triss`

Decryption is simpler, an XOR of the shares vs a more complicated symmetric
decryption process.

##### Comparison of security properties: ChaCha-20 vs `triss` on linux

Consider [ChaCha20](https://datatracker.ietf.org/doc/html/rfc8439#section-2.4),
a modern stream cipher and symmetric encryption algorithm. It generates a
pseudorandom keystream from a 256 bit key and other fixed size input, then XORs
that stream with the plaintext to produce ciphertext.

And consider `triss` running on linux, for which shares of the secret are
generated by a ChaCha based CSPRNG. The shares resemble keystreams as generated
by ChaCha20, see also [randomness](#randomness) above. Then `triss` does the
XORing of plaintext and keystream shares to produce the final ciphertext share.

If we assume the linux CSPRNG keystream is as secure as ChaCha20's, then then we
can assume `triss` is as secure as a ChaCha20 based symmetric encryption secret
sharing scheme. The essential difference is that `triss` saves the entire
keystreams (the CSPRNG outputs) instead of just the 256 bit keys.

In this context, "secure" means that it is computationally infeasible for an
attacker with partial knowledge of the keystream to determine more of it.


### Implementation

Important modules are:

[triss.crypto](src/triss/crypto.py)
[triss.codec](src/triss/codec/__init__.py)
[triss.codec.data_file](src/triss/codec/data_file.py)
[triss.codec.qrcode](src/triss/codec/qrcode.py)

And the entrypoint is from [triss.cli](src/triss/cli.py) into
[triss.core](src/triss/core.py).

A few other notes:

#### Fragments and Segments

When splitting a secret, `triss` breaks input data into segments, then splits
each segment into encrypted fragments via [trivial secret
sharing](#how-does-it-work), and finally assigns fragments of segments to
shares, such that a share has a fragment of each segment.

A 3-of-3 split of 2 segments results in the following fragment-to-share
assignment:
```
share 1:
   - segment1_fragment1
   - segment2_fragment1
share 2:
   - segment1_fragment2
   - segment2_fragment2
share 3:
   - segment1_fragment3
   - segment2_fragment3
```

To recover the secret `triss` combines the fragments of each segment, then
concatenates the segments in order to reproduce the original input.

#### M-of-N shared secrets

To make `M-of-N` shared secrets, `triss` performs $\binom{N}{M}$ `M-of-M`
splits. One such `M`-way split is called an "authorized set", and the secret is
recoverable given all elements of any one authorized set. The elements are
bundled into `N` shares, such that every subset of shares of size `M` has
exactly one complete authorized set. For example, a `2-of-4` split requires
`$\binom{4}{2}$ = 6` authorized sets, any 2 shares have one element each of the
same authorized set, and each share ends up with elements from 3 different
authorized sets.

```
2 elements of each authorized set are assigned to 2 of 4 shares.
Authorized set:  A   B   C   D   E   F
       share 1:  A1  B1  C1
       share 2:  A2          D1  E1
       share 3:      B2      D2      F1
       share 4:          C2      E2  F2
```

In this example, each authorized set element is a fragment of the only segment
of the input.

#### File format

When splitting a secret, `triss` creates a top-level output directory with one
subdirectory per share, and multiple files per share directory. Each output file
consists of a fixed size header followed by data. There are 2 output modes,
`DATA` and `QRCODE`. `DATA` file size is unlimited, but QR codes have a
relatively low maximum capacity, so larger input is broken up into multiple
segments.

##### Header format

Headers are defined in the [triss.header](src/triss/header.py) module.

The `FragmentHeader` describes a file that contains a fragment of a split
segment of a secret. The header contains, among other things:
- An authorized set ID, used to identify which of the authorized sets the
  fragment belongs to.
- A fragment ID, used to differentiate fragments (elements of a single
  authorized set), and to determine whether an authorized set is complete, and
  thus can be combined to produce a decrypted result.
- A segment ID, used to position the decrypted result in the final output.

The `MacHeader` describes a file that contains MACs (message authentication
codes) of fragments. It describes the MAC algorithm and key size, so `triss` can
parse the file's payload into a key and MAC digests.

##### MAC payload layout

Consider an authorized set `A` of 3 elements `A1`, `A2`, `A3`, each of which
contains a fragment from 2 segments.

`A1s0` means authorized set `A`, fragment `1`, segment `0`. The 6 fragments are
assigned to 3 shares as follows:
```
  share 0: A1s0, A1s1
  share 1: A2s0, A2s1
  share 2: A3s0, A3s1
```

Each share receives MAC digests of all fragments in segment-major order, but
note that each share only has the MAC key for its own fragments. `A1_key` is the
MAC key for fragment `A1`, used to compute the MAC digests for both segments
`A1s0` and `A1s1`: `A1s0_MAC = MAC(A1_key, A1s0)` and `A1s1_MAC = MAC(A1_key,
A1s1)`. The payload consists of key bytes and digest bytes concatenated without
padding.

```
  share 0: A1_key, A1s0_MAC, A2s0_MAC, A3s0_MAC, A1s1_MAC, A2s1_MAC, A3s1_MAC
  share 1: A2_key, A1s0_MAC, A2s0_MAC, A3s0_MAC, A1s1_MAC, A2s1_MAC, A3s1_MAC
  share 2: A3_key, A1s0_MAC, A2s0_MAC, A3s0_MAC, A1s1_MAC, A2s1_MAC, A3s1_MAC
                   ^-- segment 0                 ^-- segment 1
```


## License

GNU General Public License v3.0 or later

See [COPYING](COPYING) to see the full text.
