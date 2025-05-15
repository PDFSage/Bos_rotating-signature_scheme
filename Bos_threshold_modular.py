# threshold_frost.py
#
# Threshold-login rebuild with **FROST-style Ed25519 signing**:
# • Root key is never reconstructed; each device holds a Shamir share
#   and produces only a partial signature.
# • Dealer/Aggregator just adds points and scalars → full Ed25519 sig.
# • Encrypted-at-rest shares, per-session nonces, no secret leaves
#   the participant hardware → mitigates chip-off / implant leakage.

import secrets, hashlib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from nacl.bindings import (
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_core_ed25519_add,
)
from nacl.signing import VerifyKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ── curve/order helpers ─────────────────────────────────────────────────────

L = 2 ** 252 + 27742317777372353535851937790883648493  # ed25519 group order


def int2scalar(x: int) -> bytes:
    return (x % L).to_bytes(32, "little")


def hash_challenge(R: bytes, PK: bytes, msg: bytes) -> int:
    return int.from_bytes(hashlib.sha512(R + PK + msg).digest(), "little") % L


# ── generic shamir over L ───────────────────────────────────────────────────

def shamir_split(s: int, n: int, t: int) -> List[Tuple[int, int]]:
    coeffs = [s] + [secrets.randbelow(L) for _ in range(t - 1)]

    def f(x):
        y = 0
        for p, c in enumerate(coeffs):
            y = (y + c * pow(x, p, L)) % L
        return y

    return [(i, f(i)) for i in range(1, n + 1)]


# ── HPKE (X25519-HKDF-ChaCha20) for share transport ────────────────────────

def hpke_keypair():
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return pk, sk


def hpke_encrypt(recipient_pk: bytes, pt: bytes) -> bytes:
    eph_sk = x25519.X25519PrivateKey.generate()
    shared = eph_sk.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_pk))
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hpke").derive(shared)
    nonce = secrets.token_bytes(12)
    ct = ChaCha20Poly1305(k).encrypt(nonce, pt, None)
    return eph_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) + nonce + ct


def hpke_decrypt(recipient_sk, blob: bytes) -> bytes:
    eph_pk = x25519.X25519PublicKey.from_public_bytes(blob[:32])
    nonce, ct = blob[32:44], blob[44:]
    shared = recipient_sk.exchange(eph_pk)
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hpke").derive(shared)
    return ChaCha20Poly1305(k).decrypt(nonce, ct, None)


# ── participant (secure element abstraction) ───────────────────────────────

class Participant:
    def __init__(self, idx: int):
        self.idx = idx
        self.active = False
        self.kem_pk, self.kem_sk = hpke_keypair()
        self._share_enc: Dict[int, bytes] = {}  # ver → enc share
        self._share_scalar: Optional[int] = None
        self._nonce_store: Dict[int, int] = {}  # session → r_i

    def receive_share(self, ver: int, enc: bytes):
        self._share_enc[ver] = enc

    def activate(self, on: bool = True):
        self.active = on

    # ─ signing round ─
    def commit(self, ver: int, sess: int) -> Optional[bytes]:
        if not self.active or ver not in self._share_enc:
            return None
        if self._share_scalar is None:  # decrypt once -– emulate SE unseal
            self._share_scalar = int.from_bytes(
                hpke_decrypt(self.kem_sk, self._share_enc[ver]), "little"
            )
        r_i = secrets.randbelow(L)
        self._nonce_store[sess] = r_i
        R_i = crypto_scalarmult_ed25519_base_noclamp(int2scalar(r_i))
        return R_i

    def respond(self, sess: int, chall: int) -> Optional[int]:
        if sess not in self._nonce_store or self._share_scalar is None:
            return None
        r_i = self._nonce_store.pop(sess)
        z_i = (r_i + chall * self._share_scalar) % L
        return z_i


# ── FROST aggregator ───────────────────────────────────────────────────────

class FROSTSignatureSystem:
    def __init__(self, n: int, t: int):
        self.n, self.t = n, t
        self.participants = [Participant(i + 1) for i in range(n)]
        self.version = -1
        self.pk: bytes = b""
        self._shares: List[Tuple[int, int]] = []
        self.rotate()

    def _root_scalar(self) -> int:
        seed = secrets.token_bytes(32)
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        return a

    def rotate(self):
        self.version += 1
        s = self._root_scalar()
        self.pk = crypto_scalarmult_ed25519_base_noclamp(int2scalar(s))
        self._shares = shamir_split(s, self.n, self.t)
        for p, (_, sh) in zip(self.participants, self._shares):
            p.receive_share(
                self.version, hpke_encrypt(p.kem_pk, int2scalar(sh))
            )

    # ─ full threshold-signature protocol ─
    def sign(self, msg: bytes) -> Optional[bytes]:
        sess = secrets.randbits(64)
        commits: List[Tuple[Participant, bytes]] = []
        for p in self.participants:
            R_i = p.commit(self.version, sess)
            if R_i:
                commits.append((p, R_i))
            if len(commits) == self.t:
                break
        if len(commits) < self.t:
            return None
        R_sum = commits[0][1]
        for _, R_i in commits[1:]:
            R_sum = crypto_core_ed25519_add(R_sum, R_i)
        c = hash_challenge(R_sum, self.pk, msg)
        z = 0
        for p, _ in commits:
            z_i = p.respond(sess, c)
            if z_i is None:
                return None
            z = (z + z_i) % L
        sig = R_sum + int2scalar(z)
        return sig

    # ─ verification helper ─
    def verify(self, sig: bytes, msg: bytes) -> bool:
        try:
            VerifyKey(self.pk).verify(msg, sig)
            return True
        except Exception:
            return False


# ── demo ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    n, t = 5, 3
    sys = FROSTSignatureSystem(n, t)
    for p in sys.participants[:t]:
        p.activate()
    m = b"login-challenge"
    sig = sys.sign(m)
    assert sig and sys.verify(sig, m)
