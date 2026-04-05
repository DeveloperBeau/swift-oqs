# ``OQS``

Post-quantum cryptography for Swift.

## Overview

OQS provides type-safe access to post-quantum key encapsulation and digital signature algorithms. Each algorithm is its own namespace with `PrivateKey` and `PublicKey` types.

### Key Encapsulation (KEM)

Generate a key pair, generate a shared secret, and decrypt it:

```swift
let privateKey = try MLKEM768.PrivateKey()
let result = try privateKey.publicKey.generateSharedSecret()

// Send result.ciphertext to the other party
let sharedSecret = try privateKey.decryptSharedSecret(result.ciphertext)
```

### Digital Signatures

Sign a message and verify the signature:

```swift
let signingKey = try Falcon512.PrivateKey()
let signature = try signingKey.signature(for: message)
let valid = try signingKey.publicKey.isValidSignature(signature, for: message)
```

## Why Post-Quantum?

Today's most widely used encryption -- RSA and elliptic-curve cryptography -- relies on math problems that ordinary computers find impossibly hard: factoring huge numbers and computing discrete logarithms. A sufficiently powerful quantum computer could solve both problems quickly, breaking these algorithms entirely.

That future may be years away, but the threat is real *now*. Adversaries can record encrypted traffic today and store it until a quantum computer is available to decrypt it. This is called **"harvest now, decrypt later"**, and it means anything encrypted with traditional algorithms may already be at risk if the data has a long shelf life.

The algorithms in this library are built on different math problems that quantum computers cannot solve efficiently:

| Family | Approach | Type |
|---|---|---|
| ML-KEM | Lattice math (structured lattices) | Key encapsulation |
| Classic McEliece | Error-correcting codes (50+ years of study) | Key encapsulation |
| HQC | Error-correcting codes | Key encapsulation |
| Falcon | Lattice math (structured lattices) | Signatures |
| SPHINCS+ / SLH-DSA | Hash functions only -- no algebraic structure to attack | Signatures |
| CROSS | Error-correcting codes | Signatures |

These algorithms were selected by NIST (the U.S. National Institute of Standards and Technology) after an eight-year public evaluation involving researchers worldwide.

## Why Shared Secrets and Symmetric Keys?

Post-quantum algorithms are powerful, but they come with trade-offs: their keys are larger and the operations are slower compared to symmetric encryption (algorithms like AES-256 or ChaCha20 that use a single shared key for both encryption and decryption).

The good news is that symmetric encryption is already quantum-resistant. A quantum computer's best attack on AES (Grover's algorithm) only halves the effective security level, so AES-256 still provides 128-bit security against quantum attackers -- more than enough.

This is why the standard pattern is a two-step process:

1. **Key exchange**: Use a KEM (key encapsulation mechanism) to safely establish a shared secret between two parties. The KEM handles the hard part -- getting both sides to agree on the same secret without an eavesdropper being able to figure it out.
2. **Bulk encryption**: Use that shared secret as the key for fast symmetric encryption (AES-256, ChaCha20, etc.) to encrypt the actual data.

This is the same approach used by TLS (the protocol behind HTTPS), Signal, and every modern encrypted protocol. The only difference is that the KEM replaces the old key exchange method (Diffie-Hellman or ECDH) with a quantum-safe version.

The shared secret produced by a KEM is typically 32 bytes -- exactly the right size to use directly as an AES-256 or ChaCha20 key. You get quantum-safe key exchange *and* fast symmetric encryption for bulk data.

## Topics

### Key Encapsulation

- ``MLKEM512``
- ``MLKEM768``
- ``MLKEM1024``
- ``HQC128``
- ``HQC192``
- ``HQC256``
- ``ClassicMcEliece348864``
- ``ClassicMcEliece460896``
- ``ClassicMcEliece6688128``
- ``ClassicMcEliece6960119``
- ``ClassicMcEliece8192128``

### Digital Signatures

- ``Falcon512``
- ``Falcon1024``
- ``FalconPadded512``
- ``FalconPadded1024``
- ``SPHINCSSHA2128fSimple``
- ``SPHINCSSHA2256fSimple``
- ``CrossRSDP128Fast``
- ``SLHDSAPureSHA2128f``

### Shared Types

- ``SharedSecret``
- ``SharedSecretResult``
- ``OQSError``
