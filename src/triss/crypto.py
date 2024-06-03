# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import functools
import itertools
import hmac
import math
import re
import secrets

def fletchers_checksum_16(xs):
    """
    Return 2 byte fletcher's checksum.
    """
    c = 0
    n = 0
    for x in xs:
        n = (n + x)  # running sum, order independent
        c = (c + n)  # sum of running sums, depends on order
    return bytes([c % 255, n % 255])


def xor_bytes(xs, ys):
    if len(xs) != len(ys):
        raise ValueError("Refusing to xor byte strings of different length: "
                         f"len(xs) = {len(xs)}, len(ys) = {len(ys)}.")
    return bytes(b1 ^ b2 for b1, b2 in zip(xs, ys))


def split_secret(secret_bytes, n):
    """Return generator that produces N ciphertext fragments of SECRET_BYTES.

    Given all N fragments, SECRET_BYTES can be reproduced with
    combine_fragments. Each fragment is a byte string of the same length as
    SECRET_BYTES and posession of less than N fragments gives no information
    about SECRET_BYTES except its maximum length. Fragments are constructed
    like a one-time pad: with N=2, this function yields a one-time pad and its
    key as the 2 fragments. With N>2, it XORs additional keys into the pad, and
    returns all the keys and the pad."""
    n_keys = int(n) - 1
    if n_keys < 1:
        raise ValueError(
            "Refusing to return secret_bytes without splitting, require at least "
            "N=2 fragments. Check number of shares.")

    one_time_pad = list(secret_bytes)
    k = len(one_time_pad)
    for _ in range(n_keys):
        key = secrets.token_bytes(k)
        one_time_pad = xor_bytes(one_time_pad, key)
        yield key
    yield one_time_pad


def combine_fragments(fragments):
    """Combine FRAGMENTS and return secret bytes. Inverse of split_secret.

    FRAGMENTS is a collection of byte strings of equal length."""
    it = iter(fragments)
    secret_bytes = next(it)
    for frag in it:
        secret_bytes = xor_bytes(secret_bytes, frag)
    return secret_bytes

# list(combine_fragments(split_secret([0, 1, 2, 3, 4, 5, 6, 7, 8], 3)))

def m_of_n_access_structure(m, n):
    """Return an access structure for an M-of-N trivial secret sharing scheme

    as a list of authorized sets. This scheme divides a secret into N shares
    such that:
    - Any subset of M shares can be used to recover the secret (M <= N). Each
      such subset is an "authorized set".
    - Any subset of fewer than M shares yields no information about the secret
      except its maximum length.

    The collection of all authorized sets is the "access structure". In this
    scheme, the access structure is the set of (N choose M) unique authorized
    sets. The M shares of an authorized set are each assigned a different one
    of M fragments of the secret, produced by the split_secret(secret_data, M)
    function, called once per authorized set. Each share ends up with a
    fragment from (N-1 choose M-1) of the authorized sets (see
    num_asets_per_share for explanation).

    Identify both shares and authorized sets by 0-based integer ids. Return the
    access structure as a list of authorized sets, in which each authorized set
    enumerates share ids its fragments are assigned to.

    ==== Example Outputs ====
       m_of_n_access_structure(2, 2)
    => [{'aset_id': 0, 'share_ids': [0, 1]}]

       m_of_n_access_structure(2, 4)
    => [{'aset_id': 0, 'share_ids': [0, 1]},
        {'aset_id': 1, 'share_ids': [0, 2]},
        {'aset_id': 2, 'share_ids': [0, 3]},
        {'aset_id': 3, 'share_ids': [1, 2]},
        {'aset_id': 4, 'share_ids': [1, 3]},
        {'aset_id': 5, 'share_ids': [2, 3]}]

    ==== More Examples ====
    Each row is a share, each column an authorized set, and each cell a
    fragment, named by letter+ordinal, e.g. A1, representing the outputs of the
    split_secret function. The call "A" to split_secret produced fragments "A1"
    and "A2". (A1 cannot be combined with B2 since they were produced by 2
    separate calls to split_secret).

    2-of-2: 1 authorized set
    aset_id:   0
    share 0:  A1
    share 1:  A2

    2-of-3: 3 authorized sets
    aset_id:   0  1  2
    share 0:  A1  B1
    share 1:  A2      C1
    share 2:      B2  C2

    2-of-4: 6 authorized sets
    aset_id:   0   1   2   3   4   5
    share 0:  A1  B1  C1
    share 1:  A2          D1  E1
    share 2:      B2      D2      F1
    share 3:          C2      E2  F2
    """
    aset_ids = range(num_asets(m, n))
    authorized_sets = [{'aset_id': i} for i in aset_ids]
    share_ids = range(n)
    # share_subset is the subset of size m of shares that the authorized set
    # identified by aset_id is assigned to.
    for (aset_id,
         share_subset) in zip(aset_ids,
                              itertools.combinations(share_ids, m)):
        authorized_sets[aset_id]['share_ids'] = share_subset
    return authorized_sets


def num_asets(m, n):
    """Return the number of authorized sets for an M-of-N split

    which is (N choose M). An authorized set is a subset of shares of size M,
    and there are a total of N shares, and (N choose M) counts the number of
    such subsets.
    """
    return math.comb(n, m)


def num_asets_per_share(m, n):
    """Return the number of fragments assigned to a share of an M-of-N split

    which is (N-1 choose M-1).

    ==== Explanation ====
    Choose one of the N shares to examine. Each of the K authorized sets that
    assign it a fragment must assign their remaining M-1 fragments to a unique
    set of the remaining N-1 shares: there are K = (N-1 choose M-1) ways to do
    this.

    NOTE K can also be computed as (N choose M) * M/N which expresses the total
    number of secret fragments across all authorized sets evenly divided among
    the shares. But prefer the math.comb method to avoid division.

    ==== Example ====
    Consider a 3-of-5 split with a total of (5 choose 3) = 10 authorized sets A
    through J, and examine share 0. Each of the K authorized sets that assign
    it a fragment must assign their remaining 2 fragments to a unique set of
    the remaining 4 shares. There are 6 = (4 choose 2) ways to do this, see the
    assignments of fragments 2 and 3 of authorized sets A through F:

    share 0:  A1  B1  C1  D1  E1  F1

    share 1:  A2  B2  C2               G1 H1 I1
    share 2:  A3          D2  E2       G2 H2    J1
    share 3:      B3      D3      F2   G3    I2 J2
    share 4:          C3      E3  F3      H4 I3 J3
    """
    return math.comb(n - 1, m - 1)


DEFAULT_ALGORITHM = "hmac-sha384"
# Allow up to 64KB of key material. Set a limit to prevent overflow errors
# constructing hmac objects. Typical keys are usually the same size as the MAC
# digest, e.g. 48 bytes (384 bits) for hmac-sha384.
MAX_KEY_SIZE = 64 * 1024

@functools.lru_cache
def digest_size_bytes(algo):
    if not algo.startswith("hmac-"):
        raise ValueError("Unsupported MAC algorithm. Triss only supports HMAC "
                         "so algorithm name should start with 'hmac-' but "
                         f"got '{algo}'")
    digestmod = re.sub('^hmac-', '', algo.lower())
    return hmac.new(b'', digestmod=digestmod).digest_size

def new_mac_key(algo=DEFAULT_ALGORITHM):
    # At least 256 bits (32 bytes) of key material.
    key_size = max(32, digest_size_bytes(algo))
    return secrets.token_bytes(key_size)

def new_mac(key, algo=DEFAULT_ALGORITHM):
    """
    Return new KeyedHmac of SIZE_BITS, the size in bits

    of both the secret key and the digest.
    """
    if len(key) < digest_size_bytes(algo):
        raise ValueError(
            f"MAC key is too short: got {len(key)} bytes but require at least "
            f"{digest_size_bytes(algo)} for {algo}.")
    if len(key) > MAX_KEY_SIZE:
        raise ValueError(
            f"MAC key is too big: got {len(key)} bytes but max size is "
            f"{MAX_KEY_SIZE}")
    digestmod = re.sub('^hmac-', '', algo.lower())
    return hmac.new(key, digestmod=digestmod)

digests_equal = hmac.compare_digest
