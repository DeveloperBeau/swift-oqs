import Foundation
internal import Cliboqs

/// Falcon-1024 digital signatures.
///
/// Falcon-1024 is a lattice-based signature scheme providing 256-bit security with compact signatures.
///
/// ## Usage
///
/// ```swift
/// // Generate a signing key
/// let signingKey = try Falcon1024.PrivateKey()
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
/// let imported = try Falcon1024.PrivateKey(
///     rawRepresentation: keyData,
///     publicKeyRepresentation: pubData
/// )
/// ```
public enum Falcon1024: Sendable {
    static let algorithmName = "Falcon-1024"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: Falcon1024.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: Falcon1024.algorithmName)
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
            try sigSign(algorithm: Falcon1024.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: Falcon1024.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: Falcon1024.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
