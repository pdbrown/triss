# Triss

Information theoretically secure **TRI**vial **S**ecret **S**haring.

Split a secret into `N` shares, such that every subset of `M` shares contains
the information needed to reconstruct the secret. No subset smaller than `M`
reveals any information about the secret, except its maximum size.


## What is this for?

Use this to make backups of your secrets (passwords, gpg keys, etc.) without
having to remember anything, except where you leave the shares.

Say you split a secret into `N = 3` shares, requiring `M = 2` shares to recover
it. Then give one share to your best friend, another to your lawyer, and keep
the third one. You trust your lawyer not to collude with your friend, and if you
ever forget your secret, you can recover it as long as you can get 2 of the 3
shares. When you die, your friend and lawyer can discover what you've been
hiding all these years.

You can distribute shares in `DATA` file format, or print them onto paper in
`QRCODE` format.


## How does it work?

Trivial secret sharing is dead simple and works by XORing the secret with a
random number. This is the same idea as a
[one-time pad](https://en.wikipedia.org/wiki/One-time_pad).

For a 2-of-2 split:
- Represent your secret as a binary number `S`.
- Securely generate an unguessable random number `K` of the same length as `S`.
- Combine `S` and `K` to make `P = S xor K`.
- Distribute `P` and `K` as the 2 shares of the secret.
- Recover the secret by combining them: `P xor K = S`.

For `N of N` splits with more shares, generate more keys `K2`, `K3`, etc and XOR
them all into `S` to make `P`. The shares are `P` and all keys `K`, `K2`, `K3`,
etc.

For `M of N` splits where `M < N`, make a separate `M of M` split for each
of the $\binom{N}{M}$ subsets.


## Installation

### Prerequisites
There are no prerequisites for `DATA` file mode, but the `QRCODE` mode
depends on [`qrencode`](https://github.com/fukuchi/libqrencode) and
[`zbarimg`](https://github.com/mchehab/zbar).

```
| Dependency  | Minimum Version |   Released |
|-------------+-----------------+------------|
| libqrencode |           4.1.1 | 2020-09-28 |
| zbarimg     |          0.23.1 | 2020-04-20 |
```

Note the minimum version of `zbarimg` is a hard requirement, because support for
binary data was added in `0.23.1`, and that older versions of `qrencode` may
work, but haven't been tested.

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

See also
[zbar](https://github.com/mchehab/zbar/tree/6092b033b35fdcc7ee95fc366ed303f475739bfc).

### Dist Package
The following steps usually happen in a python virtual environment. Set one up
like this:
```bash
$(command -v python3 || command -v python) -m venv venv
source venv/bin/activate
```

Then either install directly:
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
triss combine [-h] [-c {DATA,QRCODE}] [-o OUT_FILE] DIR [DIR ...]

positional arguments:
  DIR               one or more directories containing input files to combine

options:
  -h, --help        show this help message and exit
  -c {DATA,QRCODE}  input file format, will guess if omitted
  -o OUT_FILE       write secret to output file, or stdout if omitted
```

## Examples

Prepare a demo secret for the following examples.
```bash
echo "Not a real secret -____-" > demosecret.txt
```

### Split secret in DATA mode

Shares of the secret are stored in plain binary files. This handy when the
secret is large and you don't care about printing the shares onto paper.

```bash
# Make 2-of-4 split
triss split -i demosecret.txt -m 2 4 data-shares
```

### Split secret in QRCODE mode

Shares of the secret are produced the same way as in DATA mode, then encoded as
QR codes. This allows you to print them onto paper, but can be slow and
cumbersome for large secrets. Each QR code stores up to 1273 bytes, and is
generated with error correction set to "High", so is scannable as long as at
least 70% of the original image is available.

```bash
# Make a 2-of-4 split in QRCODE mode
triss split -i demosecret.txt -c QRCODE -t mysecret -m 2 4 qr-shares
```

### Recover secret

```bash
# Recover from data shares
triss combine -o recovered_01.txt data-shares/share-0 data-shares/share-1

# Recover from (photos of) QR codes
triss combine -o recovered_qr.txt qr-shares/share-0 qr-shares/share-1

# Demonstrate that any 2 data shares can recover the secret
for i in $(seq 0 3); do
  for j in $(seq $((i+1)) 3); do
    echo Recover secret with shares $i and $j
    triss combine -o recovered_${i}${j}.txt shares/share-$i shares/share-$j
  done
done
more recovered*.txt | cat
```

Each share is put into its own subdirectory and consists of _multiple parts_.
Make sure you keep parts of a share together and distribute complete shares with
all their parts. If any part is missing, the share is useless.

```
TODO FIXME

shares
├── share-0
│   ├── share-0_part-1_of_3.dat
│   ├── share-0_part-2_of_3.dat
│   └── share-0_part-3_of_3.dat
├── share-1
│   ├── share-1_part-1_of_3.dat
│   ├── share-1_part-2_of_3.dat
│   └── share-1_part-3_of_3.dat
├── share-2
│   ├── share-2_part-1_of_3.dat
│   ├── share-2_part-2_of_3.dat
│   └── share-2_part-3_of_3.dat
└── share-3
    ├── share-3_part-1_of_3.dat
    ├── share-3_part-2_of_3.dat
    └── share-3_part-3_of_3.dat
```



## Details

### Motivation

There are many other tools that do secret sharing, but they all seem to
implement
[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir's_secret_sharing).

- https://iancoleman.io/shamir/
- https://github.com/jesseduffield/horcrux
- http://point-at-infinity.org/ssss/
- https://github.com/cyphar/paperback

I wanted one that does trivial secret sharing, because I'm not smart enough to
understand Shamir's method and whether an implementation secure. I found trivial
secret sharing to be simpler. It's also easier to reimplement from scratch in
case the original software used to split the secret is lost or incompatible with
future operating systems.

### Cryptography

#### Randomness

This trivial secret sharing scheme relies on its random numbers being truly
random. It uses python's `secrets.token_bytes` method, which calls `os.urandom`,
which uses the `getrandom(2)` system call in blocking mode on linux (on python
version `>= 3.6` and linux kernel version `>= 3.17`).

See `man 4 random` and `man 2 getrandom`. And from `man 7 random`:

> The kernel random‐number generator relies on entropy gathered from device
drivers and other sources of environmental noise to seed a cryptographically
secure pseudorandom number generator (CSPRNG). Unless you are doing long‐term
key generation (and most likely not even then), you probably shouldn’t be
reading from the /dev/random device or employing getrandom(2) with the
GRND_RANDOM flag. Instead, either read from the /dev/urandom device or employ
getrandom(2) without the GRND_RANDOM flag. The cryptographic algorithms used for
the urandom source are quite conservative, and so should be sufficient for all
purposes.

#### Authentication

One major flaw of secret sharing schemes (at least trivial secret sharing and
Shamir's) is that there is no message authentication. An attacker or dishonest
participant can modify their share such that the combined result no longer
reproduces the original secret.

You can always do some kind of authentication outside of `triss`, but it will
affect the security properties of the resulting system.

##### A _flawed_ authentication scheme

**Don't do this!** It's just an example of why authentication is non-trivial.

Say you want to split a password into 2 shares, requiring both to recover. But
you decide you also want to authenticate the result so you'll know the recovered
password is the same as the original. You do the 2-of-2 split, then compute
sha256 hashes of both shares, and give each participant one share and both
hashes. Later when combining, each participant can verify the hash of the
other's share, and so determine whether it's been modified.

But wait! You just gave each participant all they need to crack the password:
they already hold one share, and need to guess the 2nd share to obtain the
password. They don't have the 2nd share, but they do have its sha256 hash. They
also know the length of the password (the length of their share), and if it's
short enough, they can just try every possible bit string and hash it. Once they
find a match, they've found your share, and can decrypt the password.

This attack becomes infeasible if the password is long enough, and the hash
function is expensive enough, the resulting system is no longer information
theoretically secure.

##### A better authentication scheme

```
m=3 of n=5

Segment 0:
    share 0:  A1  B1  C1  D1  E1  F1
    share 1:  A2  B2  C2               G1 H1 I1
    share 2:  A3          D2  E2       G2 H2    J1
    share 3:      B3      D3      F2   G3    I2 J2
    share 4:          C3      E3  F3      H4 I3 J3

Segment 1:
    share 0:  A1  B1  C1  D1  E1  F1
    share 1:  A2  B2  C2               G1 H1 I1
    share 2:  A3          D2  E2       G2 H2    J1
    share 3:      B3      D3      F2   G3    I2 J2
    share 4:          C3      E3  F3      H4 I3 J3


10 asets => 60 hmacs: one for each seg of eadh frag

for aset A:
  share 0: A1_key, A1_MAC, A2_MAC, A3_MAC, A1_MAC, A2_MAC, A3_MAC
  share 1: A2_key, A1_MAC, A2_MAC, A3_MAC, A1_MAC, A2_MAC, A3_MAC
  share 2: A3_key, A1_MAC, A2_MAC, A3_MAC, A1_MAC, A2_MAC, A3_MAC
                   ^-- segment 0           ^-- segment 1






Simplest Example: 2-of-2 split, 1 segment (1 aset)

Segment 0:
    share 0: A1
    share 1: A2

Player 0 gets share 0:
aset_id=0: (aset A)
- fragment 0
- MAC key_A_0 for share 0 (fragment 0)
- MAC digest of (key_A_0, fragment 0)
- MAC digest of (key_A_1, fragment 1)

Player 1 gets share 1:
aset_id=0: (aset A)
- fragment 1
- MAC key_A_1 for share 1 (fragment 1)
- MAC digest of (key_A_0, fragment 0)
- MAC digest of (key_A_1, fragment 1)

```

This is similar to the flawed one above, but uses HMAC instead of a plain hash.
Split a password into 2 shares `s1` and `s2`. Participants `p1` and `p2` each
generate a secret key `k1` and `k2`, which they keep to themselves, and h1 =
sha256(k1), h2 = sha256(k2) which are made public. p1 needs to
verify s2 later, so computes hmac(k1, s2)

p1:
s1 (private)
k1 (private)
hmac(s1, k1) = mac1(public)

and get:
mac2

but don't have:
k2, so can't brute force s2 = ? in hmac(?, k2) = mac2

at decode time, get:
k2 (can verify h2 = h(k2))
s2 (can verify mac2 = hmac(s2, k2))


p1:
s1 (private)
k1 (private)
hmac(s1, k1) = mac1(public)

and get:
mac2

but don't have:
k2, so can't brute force s2 = ? in hmac(?, k2) = mac2

at decode time, get:
k2
s2 (can verify mac2 = hmac(s2, k2))


Encrypt-then-MAC

p1: s1, k1 -> mac1
p2: s2, k2 -> mac2
p3: s3, k3 -> mac3

p1 has:
s1, k1, mac1, mac2, mac3

p2 has:
s2, k2, mac1, mac2, mac3

p3 has:
s3, k3, mac1, mac2, mac3





















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


## License

GNU General Public License v3.0 or later

See [COPYING](COPYING) to see the full text.
