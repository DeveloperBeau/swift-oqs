import Foundation
internal import Cliboqs

/// CROSS RSDP-128-balanced digital signatures.
///
/// CROSS is a code-based signature scheme. This RSDP-128 variant provides 128-bit security with balanced performance.
///
/// ## Usage
///
/// ```swift
/// // Generate a signing key
/// let signingKey = try CrossRSDP128Balanced.PrivateKey()
///
/// // Sign a message
/// let message = Data("Hello".utf8)
/// let signature = try signingKey.signature(for: message)
///
/// // Verify
/// let valid = try signingKey.publicKey.isValidSignature(signature, for: message)
///
/// // Export keys
/// let keyData = signingKey.rawRepresentation
/// let pubData = signingKey.publicKey.rawRepresentation
///
/// // Import keys
/// let imported = try CrossRSDP128Balanced.PrivateKey(
///     rawRepresentation: keyData,
///     publicKeyRepresentation: pubData
/// )
/// ```
public enum CrossRSDP128Balanced: Sendable {
    static let algorithmName = "cross-rsdp-128-balanced"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: CrossRSDP128Balanced.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: CrossRSDP128Balanced.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        public func signature(for data: Data) throws -> Data {
            try sigSign(algorithm: CrossRSDP128Balanced.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: CrossRSDP128Balanced.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: CrossRSDP128Balanced.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
