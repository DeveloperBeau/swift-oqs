# ``OQS``

Post-quantum cryptography for Swift.

## Overview

OQS provides type-safe access to post-quantum key encapsulation and digital signature algorithms. Each algorithm is its own namespace with `PrivateKey` and `PublicKey` types.

### Key Encapsulation (KEM)

Generate a key pair, encapsulate a shared secret, and decapsulate it:

```swift
let privateKey = try MLKEM768.PrivateKey()
let sealed = try privateKey.publicKey.encapsulate()

// Send sealed.ciphertext to the other party
let sharedSecret = try privateKey.decapsulate(sealed.ciphertext)
```

### Digital Signatures

Sign a message and verify the signature:

```swift
let signingKey = try Falcon512.PrivateKey()
let signature = try signingKey.signature(for: message)
let valid = try signingKey.publicKey.isValidSignature(signature, for: message)
```

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
- ``EncapsulationResult``
- ``OQSError``
