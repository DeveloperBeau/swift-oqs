import Foundation
internal import Cliboqs

/// HQC-192 key encapsulation.
///
/// HQC-192 is a code-based KEM and NIST candidate providing 192-bit security.
///
/// ## Usage
///
/// ```swift
/// // Generate a key pair
/// let privateKey = try HQC192.PrivateKey()
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
/// let imported = try HQC192.PrivateKey(
///     rawRepresentation: keyData,
///     publicKeyRepresentation: pubData
/// )
/// ```
public enum HQC192: Sendable {
    static let algorithmName = "HQC-192"

    /// A HQC192 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: HQC192.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: HQC192.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: HQC192.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A HQC192 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: HQC192.algorithmName)
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
            let result = try kemEncapsulate(algorithm: HQC192.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
