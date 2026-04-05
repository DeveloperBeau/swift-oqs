# swift-oqs

[![CI](https://github.com/DeveloperBeau/swift-oqs/actions/workflows/ci.yml/badge.svg)](https://github.com/DeveloperBeau/swift-oqs/actions/workflows/ci.yml)

Post-quantum cryptography for Swift, powered by [liboqs](https://github.com/open-quantum-safe/liboqs).

## Features

- Type-safe Swift API for key encapsulation (KEM) and digital signatures
- Vendored liboqs C source -- no system dependencies or extra build steps
- Full Swift 6 concurrency support (`Sendable` throughout)
- Builds on macOS and Linux via Swift Package Manager

## Requirements

- Swift 6.3+
- macOS 13+ / iOS 16+ / tvOS 16+ / watchOS 9+ / Linux

## Installation

Add swift-oqs as a dependency in your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/DeveloperBeau/swift-oqs.git", from: "0.1.0"),
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

// Generate a key pair
let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)

// Encapsulate -- produces a ciphertext and shared secret
let result = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)

// Decapsulate -- recovers the same shared secret
let sharedSecret = try KEM.decapsulate(
    algorithm: .mlkem768,
    ciphertext: result.ciphertext,
    secretKey: keyPair.secretKey
)

assert(result.sharedSecret == sharedSecret)
```

### Digital Signatures

```swift
import OQS

let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)

let message = Data("Hello, post-quantum world!".utf8)
let signature = try Signature.sign(algorithm: .falcon512, message: message, secretKey: keyPair.secretKey)

let valid = try Signature.verify(
    algorithm: .falcon512,
    message: message,
    signature: signature,
    publicKey: keyPair.publicKey
)

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
