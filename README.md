# swift-oqs

[![CI](https://github.com/DeveloperBeau/swift-oqs/actions/workflows/ci.yml/badge.svg)](https://github.com/DeveloperBeau/swift-oqs/actions/workflows/ci.yml)

Post-quantum cryptography for Swift, powered by [liboqs](https://github.com/open-quantum-safe/liboqs).

## Features

- Type-safe Swift API for key encapsulation (KEM) and digital signatures
- Vendored liboqs C source -- no system dependencies or extra build steps
- Full Swift 6 concurrency support (`Sendable` throughout)
- Builds on macOS and Linux via Swift Package Manager

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

These algorithms were selected by NIST (the U.S. National Institute of Standards and Technology) after an eight-year public evaluation involving researchers worldwide. They represent the current best candidates for encryption that will remain secure even after large-scale quantum computers exist.

## Why Shared Secrets and Symmetric Keys?

Post-quantum algorithms are powerful, but they come with trade-offs: their keys are larger and the operations are slower compared to symmetric encryption (algorithms like AES-256 or ChaCha20 that use a single shared key for both encryption and decryption).

The good news is that symmetric encryption is already quantum-resistant. A quantum computer's best attack on AES (Grover's algorithm) only halves the effective security level, so AES-256 still provides 128-bit security against quantum attackers -- more than enough.

This is why the standard pattern is a two-step process:

1. **Key exchange**: Use a KEM (key encapsulation mechanism) to safely establish a shared secret between two parties. The KEM handles the hard part -- getting both sides to agree on the same secret without an eavesdropper being able to figure it out.
2. **Bulk encryption**: Use that shared secret as the key for fast symmetric encryption (AES-256, ChaCha20, etc.) to encrypt the actual data.

This is the same approach used by TLS (the protocol behind HTTPS), Signal, and every modern encrypted protocol. The only difference is that the KEM replaces the old key exchange method (Diffie-Hellman or ECDH) with a quantum-safe version.

The shared secret produced by a KEM is typically 32 bytes -- exactly the right size to use directly as an AES-256 or ChaCha20 key. You get quantum-safe key exchange *and* fast symmetric encryption for bulk data.

## Requirements

- Swift 6.3+
- macOS 13+ / iOS 16+ / tvOS 16+ / watchOS 9+ / Linux / Windows

## Installation

Add swift-oqs as a dependency in your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/DeveloperBeau/swift-oqs.git", from: "2.0.0"),
]
```

Then add `"OQS"` to your target's dependencies:

```swift
.target(name: "MyApp", dependencies: ["OQS"]),
```

## Usage

### Key Encapsulation (KEM)

```swift
import OQS

let privateKey = try MLKEM768.PrivateKey()
let result = try privateKey.publicKey.generateSharedSecret()
let secret = try privateKey.decryptSharedSecret(result.ciphertext)
assert(secret == result.sharedSecret)

// Use the shared secret for symmetric encryption
let symmetricKey = SymmetricKey(data: secret.rawRepresentation)
let encrypted = try AES.GCM.seal(plaintext, using: symmetricKey)
```

The shared secret can be used directly as a symmetric key, or fed into a key derivation function (like HKDF) to produce multiple keys for different purposes.

### Digital Signatures

```swift
import OQS

let signingKey = try Falcon512.PrivateKey()
let message = Data("Hello, post-quantum world!".utf8)
let signature = try signingKey.signature(for: message)
let valid = try signingKey.publicKey.isValidSignature(signature, for: message)
assert(valid)
```

## Available Algorithms

### KEM

| Family | Algorithms |
|---|---|
| ML-KEM | `mlkem512`, `mlkem768`, `mlkem1024` |
| Classic McEliece | `classicMcEliece348864`, `classicMcEliece460896`, `classicMcEliece6688128`, `classicMcEliece6960119`, `classicMcEliece8192128` |
| HQC | `hqc128`, `hqc192`, `hqc256` |

### Signatures

| Family | Algorithms |
|---|---|
| Falcon | `falcon512`, `falcon1024`, `falconPadded512`, `falconPadded1024` |
| SPHINCS+ | SHA2 and SHAKE variants at 128/192/256-bit security, fast and small |
| CROSS | RSDP and RSDPG variants at 128/192/256-bit security |
| SLH-DSA | Pure SHA2 and SHAKE variants at 128/192/256-bit security |

### Disabled Algorithms

Some algorithms from liboqs are not currently enabled in the vendored build:

- **ML-DSA** (Dilithium) -- requires AVX2 intrinsics that break portable C builds
- **BIKE** -- requires platform-specific optimizations
- **FrodoKEM** -- excluded to reduce binary size

These can be enabled by modifying `oqsconfig.h` and the `Package.swift` exclude list if your platform supports them.

## Vendored liboqs

This package vendors liboqs **0.15.0** directly as C source. No pre-built binaries or system library installation required.

The `scripts/vendor-liboqs.sh` script handles downloading and extracting a new liboqs release. A GitHub Actions workflow runs weekly to check for updates and open a PR automatically.

To update manually:

```bash
echo "0.16.0" > LIBOQS_VERSION
./scripts/vendor-liboqs.sh
swift build && swift test
```

## License

MIT. See [LICENSE](LICENSE).

liboqs is also [MIT licensed](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt).
