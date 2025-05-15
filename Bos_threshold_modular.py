# threshold_modular.py
#
# Threshold login with *asym-rotational* root-key upgrades.
# Each call to rotate() switches to the **next** CryptoSuite in
# SUITES[], e.g. Ed25519  → P-256 → Ed25519 … (asymmetric cycle).
# All other mechanics are unchanged.

import secrets, functools
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    x25519,
    ec,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ---------- generic shamir (field enlarged for ≥256-bit secrets) ----------

FIELD = 2**521 - 1  # fits P-256, Ed25519, etc.
INV = lambda x: pow(x, FIELD - 2, FIELD)


def shamir_split(secret: int, n: int, t: int) -> List[Tuple[int, int]]:
    coeffs = [secret] + [secrets.randbelow(FIELD) for _ in range(t - 1)]

    def f(x):
        y = 0
        for p, c in enumerate(coeffs):
            y = (y + c * pow(x, p, FIELD)) % FIELD
        return y

    return [(i, f(i)) for i in range(1, n + 1)]


def shamir_combine(shares: List[Tuple[int, int]]) -> int:
    total = 0
    for j, (xj, yj) in enumerate(shares):
        num = den = 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                num = (num * -xm) % FIELD
                den = (den * (xj - xm)) % FIELD
        total = (total + yj * num * INV(den)) % FIELD
    return total


# ---------- crypto suite abstraction ----------

@dataclass
class CryptoSuite:
    name: str
    key_bytes: int
    new_priv: callable
    pub_bytes: callable
    sign: Optional[callable]
    verify: Optional[callable]


def make_ed25519_suite() -> CryptoSuite:
    def new_priv():
        return ed25519.Ed25519PrivateKey.generate()

    def pub_bytes(sk):
        return sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def _sign(sk, msg):
        return sk.sign(msg)

    def _verify(pk_bytes, sig, msg):
        ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes).verify(sig, msg)

    return CryptoSuite("ed25519", 32, new_priv, pub_bytes, _sign, _verify)


def make_p256_suite() -> CryptoSuite:
    def new_priv():
        return ec.generate_private_key(ec.SECP256R1())

    def pub_bytes(sk):
        return sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def _sign(sk, msg):
        return sk.sign(msg, ec.ECDSA(hashes.SHA256()))

    def _verify(pk_bytes, sig, msg):
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pk_bytes
        ).verify(sig, msg, ec.ECDSA(hashes.SHA256()))

    return CryptoSuite("p256", 65, new_priv, pub_bytes, _sign, _verify)


def make_x25519_dh_suite() -> CryptoSuite:
    def new_priv():
        return x25519.X25519PrivateKey.generate()

    def pub_bytes(sk):
        return sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    return CryptoSuite("x25519", 32, new_priv, pub_bytes, None, None)


HPKE_SUITE = make_x25519_dh_suite()  # used for share encryption


def hpke_encrypt(recipient_pub: bytes, plaintext: bytes) -> bytes:
    eph_sk = HPKE_SUITE.new_priv()
    shared = eph_sk.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hpke").derive(
        shared
    )
    nonce = secrets.token_bytes(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return (
        eph_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        + nonce
        + ct
    )


def hpke_decrypt(recipient_sk, blob: bytes) -> bytes:
    eph_pub = x25519.X25519PublicKey.from_public_bytes(blob[:32])
    nonce, ct = blob[32:44], blob[44:]
    shared = recipient_sk.exchange(eph_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hpke").derive(
        shared
    )
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)


# ---------- participant ----------

class Participant:
    def __init__(self, idx: int):
        self.idx = idx
        self.state = False
        self.enc_sk = HPKE_SUITE.new_priv()
        self.enc_pk = HPKE_SUITE.pub_bytes(self.enc_sk)
        self.store: Dict[int, bytes] = {}  # ver -> encrypted share

    def activate(self, on: bool = True):
        self.state = on

    def rotate_encryption_key(self) -> bytes:
        self.enc_sk = HPKE_SUITE.new_priv()
        self.enc_pk = HPKE_SUITE.pub_bytes(self.enc_sk)
        return self.enc_pk

    def receive_share(self, ver: int, enc_share: bytes):
        self.store[ver] = enc_share

    def maybe_share(self, ver: int) -> Optional[Tuple[int, int]]:
        if not self.state or ver not in self.store:
            return None
        try:
            plain = hpke_decrypt(self.enc_sk, self.store[ver])
        except Exception:
            return None
        return self.idx, int.from_bytes(plain, "big")


# ---------- asymmetric-cycle signature system ----------

class AltSignatureSystem:
    SUITES = [make_ed25519_suite(), make_p256_suite()]  # add more as desired

    def __init__(self, n: int, t: int):
        self.n, self.t = n, t
        self.participants = [Participant(i + 1) for i in range(n)]
        self.version = -1
        self.pub_key = None
        self._shares: List[Tuple[int, int]] = []
        self.rotate()

    def _new_secret_int(self, suite: CryptoSuite) -> Tuple[int, bytes]:
        sk = suite.new_priv()
        if suite.name == "p256":
            secret_int = sk.private_numbers().private_value
        else:  # ed25519
            secret_int = int.from_bytes(
                sk.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ),
                "little",
            )
        return secret_int, suite.pub_bytes(sk)

    def rotate(self):
        self.version += 1
        suite = self.SUITES[self.version % len(self.SUITES)]
        secret_int, self.pub_key = self._new_secret_int(suite)
        self._shares = shamir_split(secret_int, self.n, self.t)
        for p, (_, s) in zip(self.participants, self._shares):
            p.receive_share(
                self.version, hpke_encrypt(p.enc_pk, s.to_bytes(66, "big"))
            )

    def rewrap_share(self, participant_idx: int):
        idx = participant_idx - 1
        share_int = self._shares[idx][1]
        p = self.participants[idx]
        p.receive_share(
            self.version, hpke_encrypt(p.enc_pk, share_int.to_bytes(66, "big"))
        )

    def login(self, msg: bytes) -> Optional[bytes]:
        suite = self.SUITES[self.version % len(self.SUITES)]
        active = [s for s in (p.maybe_share(self.version) for p in self.participants) if s]
        if len(active) < self.t:
            return None
        secret_int = shamir_combine(active[: self.t])

        if suite.name == "p256":
            sk = ec.derive_private_key(secret_int, ec.SECP256R1())
            return sk.sign(msg, ec.ECDSA(hashes.SHA256()))
        else:  # ed25519
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(
                secret_int.to_bytes(32, "little")
            )
            return sk.sign(msg)


# ---------- demo ----------

if __name__ == "__main__":
    n, t = 5, 3
    msg = b"login"

    sigsys = AltSignatureSystem(n, t)
    for p in sigsys.participants[:t]:
        p.activate()

    def check():
        sig = sigsys.login(msg)
        suite = sigsys.SUITES[sigsys.version % len(sigsys.SUITES)]
        assert sig
        if suite.name == "p256":
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), sigsys.pub_key
            ).verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(sigsys.pub_key).verify(
                sig, msg
            )

    check()
    sigsys.rotate()  # switch to next algorithm (Ed25519 ↔ P-256)
    for p in sigsys.participants[:t]:
        p.activate()
    check()
