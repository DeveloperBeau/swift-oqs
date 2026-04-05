# Key Encapsulation

Establish shared secrets using post-quantum key encapsulation mechanisms.

## Overview

Key Encapsulation Mechanisms (KEMs) allow two parties to establish a shared secret. One party generates a key pair, the other encapsulates a secret to the public key, and the first party decapsulates it with their private key.

All KEM algorithms follow the same pattern:

```swift
// Generate a key pair
let privateKey = try MLKEM768.PrivateKey()

// Encapsulate (sender side)
let sealed = try privateKey.publicKey.encapsulate()
// sealed.ciphertext — send this to the key pair owner
// sealed.sharedSecret — the established secret

// Decapsulate (receiver side)
let secret = try privateKey.decapsulate(sealed.ciphertext)
// secret == sealed.sharedSecret
```

### Key Import and Export

Keys can be exported and imported using raw byte representations:

```swift
// Export
let keyData = privateKey.rawRepresentation
let pubData = privateKey.publicKey.rawRepresentation

// Import
let imported = try MLKEM768.PrivateKey(
    rawRepresentation: keyData,
    publicKeyRepresentation: pubData
)
let importedPub = try MLKEM768.PublicKey(rawRepresentation: pubData)
```

## Topics

### ML-KEM (NIST Standard)

- ``MLKEM512``
- ``MLKEM768``
- ``MLKEM1024``

### HQC

- ``HQC128``
- ``HQC192``
- ``HQC256``

### Classic McEliece

- ``ClassicMcEliece348864``
- ``ClassicMcEliece460896``
- ``ClassicMcEliece6688128``
- ``ClassicMcEliece6960119``
- ``ClassicMcEliece8192128``
