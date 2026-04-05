import Foundation
internal import Cliboqs

/// Classic McEliece 6960119 key encapsulation.
///
/// Classic McEliece 6960119 is a conservative, code-based KEM with long-standing security assumptions and very large public keys. It targets 256-bit security with a different parameter trade-off.
///
/// ## Usage
///
/// ```swift
/// // Generate a key pair
/// let privateKey = try ClassicMcEliece6960119.PrivateKey()
///
/// // Encapsulate a shared secret (sender side)
/// let sealed = try privateKey.publicKey.encapsulate()
/// // Send sealed.ciphertext to the key holder
///
/// // Decapsulate (receiver side)
/// let secret = try privateKey.decapsulate(sealed.ciphertext)
/// // secret == sealed.sharedSecret
///
/// // Export keys
/// let keyData = privateKey.rawRepresentation
/// let pubData = privateKey.publicKey.rawRepresentation
///
/// // Import keys
/// let imported = try ClassicMcEliece6960119.PrivateKey(
///     rawRepresentation: keyData,
///     publicKeyRepresentation: pubData
/// )
/// ```
public enum ClassicMcEliece6960119: Sendable {
    static let algorithmName = "Classic-McEliece-6960119"

    /// A ClassicMcEliece6960119 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece6960119.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece6960119.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        /// Decapsulates a shared secret from the given ciphertext.
        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece6960119.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A ClassicMcEliece6960119 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece6960119.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        /// Encapsulates a new shared secret to this public key.
        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: ClassicMcEliece6960119.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
