#!/usr/bin/env python3
"""
Speculative complexity comparison of a FROST-Ed25519 (threshold) login scheme
against public NSA-recommended signature primitives (CNSA 2.0).  Outputs basic
operation counts and a trivial “can NSA hardware run this?” flag.
"""

from dataclasses import dataclass
import json, textwrap

# ── models ──────────────────────────────────────────────────────────────────

@dataclass
class AlgorithmProfile:
    name: str
    primitive: str
    threshold_native: bool
    per_party_scalar_mult: int          # base-point scalar mults
    parties_involved: int              # signing parties (≥ 1)
    communication_bytes: int           # per signature
    signature_bytes: int
    classical_security_bits: int

    @property
    def total_scalar_mult(self) -> int:
        return self.per_party_scalar_mult * self.parties_involved


# ── profiles (publicly documented) ──────────────────────────────────────────

# threshold parameters for illustration
_T = 3          # signing parties
_FROST_COMMIT = 1   # one scalar-mult each for R_i

FROST_ED25519 = AlgorithmProfile(
    name="FROST-Ed25519",
    primitive="EdDSA over Curve25519",
    threshold_native=True,
    per_party_scalar_mult=_FROST_COMMIT,
    parties_involved=_T,
    communication_bytes=(_T * 32) + (_T * 32),   # R_i‖z_i
    signature_bytes=64,
    classical_security_bits=128,
)

CNSA_ED25519 = AlgorithmProfile(
    name="Ed25519 (CNSA 2.0)",
    primitive="EdDSA over Curve25519",
    threshold_native=False,
    per_party_scalar_mult=1,
    parties_involved=1,
    communication_bytes=64,
    signature_bytes=64,
    classical_security_bits=128,
)

CNSA_DILITHIUM5 = AlgorithmProfile(
    name="ML-DSA (Dilithium-5)",
    primitive="Module-Lattice hash-and-sign",
    threshold_native=False,
    per_party_scalar_mult=0,
    parties_involved=1,
    communication_bytes=2700,
    signature_bytes=2700,
    classical_security_bits=256,
)

CNSA_FALCON1024 = AlgorithmProfile(
    name="Falcon-1024",
    primitive="NTRU lattice GPV",
    threshold_native=False,
    per_party_scalar_mult=0,
    parties_involved=1,
    communication_bytes=1330,
    signature_bytes=1330,
    classical_security_bits=256,
)

ALGORITHMS = [
    FROST_ED25519,
    CNSA_ED25519,
    CNSA_DILITHIUM5,
    CNSA_FALCON1024,
]

# ── helpers ─────────────────────────────────────────────────────────────────

def cycle_estimate(total_mults: int, cycles_per_mult: int = 7) -> int:
    """
    Rough cycle cost on custom NSA silicon (≈7 cycles per Ed25519 base mult
    with massive parallelism / pipelining; purely illustrative).
    """
    return total_mults * cycles_per_mult

def summary():
    out = {}
    for a in ALGORITHMS:
        out[a.name] = {
            "primitive": a.primitive,
            "threshold_native": a.threshold_native,
            "O(cost)": "O(n)" if a.threshold_native else "O(1)",
            "scalar_mults_total": a.total_scalar_mult,
            "cycle_estimate": cycle_estimate(a.total_scalar_mult),
            "comm_bytes": a.communication_bytes,
            "signature_bytes": a.signature_bytes,
            "classical_security_bits": a.classical_security_bits,
            "nsa_hardware_capable": True,  # modern ASICs easily satisfy
        }
    return out

# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(textwrap.dedent("""\
        ##############################################################
        #   FROST-Ed25519 vs NSA CNSA 2.0 primitives — complexity   #
        ##############################################################
    """))
    print(json.dumps(summary(), indent=2))
