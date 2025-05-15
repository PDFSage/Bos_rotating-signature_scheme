# threshold_modular.py

import secrets
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ---------- shamir ----------

FIELD = 2**521 - 1
INV = lambda x: pow(x, FIELD - 2, FIELD)
SHARE_LEN = (FIELD.bit_length() + 7) // 8


def shamir_split(s: int, n: int, t: int) -> List[Tuple[int, int]]:
    coeffs = [s] + [secrets.randbelow(FIELD) for _ in range(t - 1)]

    def f(x):
        y = 0
        for p, c in enumerate(coeffs):
            y = (y + c * pow(x, p, FIELD)) % FIELD
        return y

    return [(i, f(i)) for i in range(1, n + 1)]


def shamir_combine(shares: List[Tuple[int, int]]) -> int:
    tot = 0
    for j, (xj, yj) in enumerate(shares):
        num = den = 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                num = (num * -xm) % FIELD
                den = (den * (xj - xm)) % FIELD
        tot = (tot + yj * num * INV(den)) % FIELD
    return tot


# ---------- crypto suites ----------

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

    def _sign(sk, m):
        return sk.sign(m)

    def _verify(pk, sig, m):
        ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, m)

    return CryptoSuite("ed25519", 32, new_priv, pub_bytes, _sign, _verify)


def make_p256_suite() -> CryptoSuite:
    def new_priv():
        return ec.generate_private_key(ec.SECP256R1())

    def pub_bytes(sk):
        return sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def _sign(sk, m):
        return sk.sign(m, ec.ECDSA(hashes.SHA256()))

    def _verify(pk, sig, m):
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pk
        ).verify(sig, m, ec.ECDSA(hashes.SHA256()))

    return CryptoSuite("p256", 65, new_priv, pub_bytes, _sign, _verify)


def make_x25519_suite() -> CryptoSuite:
    def new_priv():
        return x25519.X25519PrivateKey.generate()

    def pub_bytes(sk):
        return sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    return CryptoSuite("x25519", 32, new_priv, pub_bytes, None, None)


HPKE_SUITE = make_x25519_suite()


def hpke_encrypt(pk: bytes, pt: bytes) -> bytes:
    eph = HPKE_SUITE.new_priv()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk))
    k = HKDF(hashes.SHA256(), 32, None, b"hpke").derive(shared)
    n = secrets.token_bytes(12)
    ct = ChaCha20Poly1305(k).encrypt(n, pt, None)
    return (
        eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        + n
        + ct
    )


def hpke_decrypt(sk, blob: bytes) -> bytes:
    eph = x25519.X25519PublicKey.from_public_bytes(blob[:32])
    n, ct = blob[32:44], blob[44:]
    shared = sk.exchange(eph)
    k = HKDF(hashes.SHA256(), 32, None, b"hpke").derive(shared)
    return ChaCha20Poly1305(k).decrypt(n, ct, None)


# ---------- participant ----------

class Participant:
    def __init__(self, idx: int):
        self.idx = idx
        self.state = False
        self.enc_sk = HPKE_SUITE.new_priv()
        self.enc_pk = HPKE_SUITE.pub_bytes(self.enc_sk)
        self.store: Dict[int, bytes] = {}

    def activate(self, on: bool = True):
        self.state = on

    def rotate_encryption_key(self) -> bytes:
        self.enc_sk = HPKE_SUITE.new_priv()
        self.enc_pk = HPKE_SUITE.pub_bytes(self.enc_sk)
        return self.enc_pk

    def receive_share(self, ver: int, enc: bytes):
        self.store[ver] = enc

    def maybe_share(self, ver: int) -> Optional[Tuple[int, int]]:
        if not self.state or ver not in self.store:
            return None
        try:
            pt = hpke_decrypt(self.enc_sk, self.store[ver])
        except Exception:
            return None
        return self.idx, int.from_bytes(pt, "big")


# ---------- asym-cycle, quorum-gated upgrade ----------

class UpgradableSignatureSystem:
    SUITES = [make_ed25519_suite(), make_p256_suite()]

    def __init__(self, n: int, t: int):
        self.n, self.t = n, t
        self.participants = [Participant(i + 1) for i in range(n)]
        self.version = -1
        self.pub_key = b""
        self._shares: List[Tuple[int, int]] = []
        self._rotate_internal()

    def _new_secret(self, suite: CryptoSuite) -> Tuple[int, bytes]:
        sk = suite.new_priv()
        if suite.name == "p256":
            s_int = sk.private_numbers().private_value
        else:
            s_int = int.from_bytes(
                sk.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ),
                "little",
            )
        return s_int, suite.pub_bytes(sk)

    def _rotate_internal(self):
        self.version += 1
        suite = self.SUITES[self.version % len(self.SUITES)]
        s_int, self.pub_key = self._new_secret(suite)
        self._shares = shamir_split(s_int, self.n, self.t)
        for p, (_, sh) in zip(self.participants, self._shares):
            p.receive_share(self.version, hpke_encrypt(p.enc_pk, sh.to_bytes(SHARE_LEN, "big")))

    # quorum login; if upgrade=True and quorum present, cycle to next suite
    def login(self, msg: bytes, upgrade: bool = False) -> Optional[bytes]:
        suite = self.SUITES[self.version % len(self.SUITES)]
        active = [s for s in (p.maybe_share(self.version) for p in self.participants) if s]
        if len(active) < self.t:
            return None
        s_int = shamir_combine(active[: self.t])
        if suite.name == "p256":
            sk = ec.derive_private_key(s_int, ec.SECP256R1())
            sig = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
        else:
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(s_int.to_bytes(32, "little"))
            sig = sk.sign(msg)
        if upgrade:
            self._rotate_internal()
        return sig

    def rewrap_share(self, idx: int):
        i = idx - 1
        sh_int = self._shares[i][1]
        p = self.participants[i]
        p.receive_share(self.version, hpke_encrypt(p.enc_pk, sh_int.to_bytes(SHARE_LEN, "big")))


# ---------- demo ----------

if __name__ == "__main__":
    n, t = 5, 3
    msg = b"auth"

    sys = UpgradableSignatureSystem(n, t)
    for p in sys.participants[:t]:
        p.activate()

    sig1 = sys.login(msg)
    suite1 = sys.SUITES[sys.version % len(sys.SUITES)]
    suite1.verify(sys.pub_key, sig1, msg)

    sig2 = sys.login(msg, upgrade=True)  # quorum triggers upgrade to next suite
    suite2 = sys.SUITES[sys.version % len(sys.SUITES)]
    suite2.verify(sys.pub_key, sig2, msg)