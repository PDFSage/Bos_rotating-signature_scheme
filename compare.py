#!/usr/bin/env python3
from dataclasses import dataclass
import json, textwrap

@dataclass
class Impl:
    name: str
    language: str
    keygen: bool
    shamir_split: bool
    share_transport_encrypted: bool
    secure_element_abstract: bool
    commit_phase: bool
    respond_phase: bool
    aggregator: bool
    verification: bool
    json_io: bool
    threshold_native: bool

py_frost = Impl(
    name="threshold_frost.py",
    language="python",
    keygen=True,
    shamir_split=True,
    share_transport_encrypted=True,
    secure_element_abstract=True,
    commit_phase=True,
    respond_phase=True,
    aggregator=True,
    verification=True,
    json_io=False,
    threshold_native=True,
)

go_public = Impl(
    name="taurus Public struct",
    language="go",
    keygen=False,                  # only holds outputs
    shamir_split=True,             # shares assumed created elsewhere
    share_transport_encrypted=False,
    secure_element_abstract=False,
    commit_phase=False,
    respond_phase=False,
    aggregator=False,              # interpolation only for PK
    verification=False,
    json_io=True,
    threshold_native=True,
)

features = [
    "keygen",
    "shamir_split",
    "share_transport_encrypted",
    "secure_element_abstract",
    "commit_phase",
    "respond_phase",
    "aggregator",
    "verification",
    "json_io",
]

def compare(a: Impl, b: Impl):
    out = {
        "impl_a": a.name,
        "impl_b": b.name,
        "language_a": a.language,
        "language_b": b.language,
        "feature_matrix": {
            f: {"a": getattr(a, f), "b": getattr(b, f)}
            for f in features
        },
        "completeness_gap": [
            f for f in features if getattr(a, f) and not getattr(b, f)
        ],
    }
    return out

if __name__ == "__main__":
    print(textwrap.dedent("""
        #############################################
        #  completeness & feature comparison output #
        #############################################
    """))
    print(json.dumps(compare(py_frost, go_public), indent=2))
