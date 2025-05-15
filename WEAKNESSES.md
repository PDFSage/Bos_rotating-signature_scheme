1 Hardware exfiltration
If a device is compromised, rotation just gives the implant fresh material to steal.

Where the secret lives

One machine (“the dealer”) must hold the full root secret while it is generated or reconstructed to sign / derive a session key.

Each participant device always stores its own Shamir share (encrypted) and—when it is “active”—briefly holds that share in plaintext RAM.

What a hardware implant can do

In the dealer it can copy the entire root key the instant it is created.

In a participant it can leak its share every time the share is decrypted. If the attacker has implants in ≥ t devices, they can reconstruct the root key for that rotation.

Why rotation does not stop it
The implant can simply exfiltrate the new secret after every rotation. Rotating limits the value of any past leak, but a persistent implant keeps harvesting the current one.