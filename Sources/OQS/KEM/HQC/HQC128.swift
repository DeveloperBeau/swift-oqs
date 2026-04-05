import Foundation
internal import Cliboqs

/// HQC-128 key encapsulation.
///
/// HQC-128 is a code-based KEM and NIST candidate providing 128-bit security.
///
/// ## Establishing a Shared Secret
///
/// Two parties (Alice and Bob) establish a shared secret without transmitting it directly.
///
/// **Step 1 — Alice generates a key pair and shares her public key:**
/// ```swift
/// let alicePrivateKey = try HQC128.PrivateKey()
/// let alicePublicKeyData = alicePrivateKey.publicKey.rawRepresentation
/// // Send alicePublicKeyData to Bob (this is safe to share publicly)
/// ```
///
/// **Step 2 — Bob receives Alice's public key and generates a shared secret:**
/// ```swift
/// let alicePublicKey = try HQC128.PublicKey(rawRepresentation: alicePublicKeyData)
/// let result = try alicePublicKey.generateSharedSecret()
///
/// let bobSharedSecret = result.sharedSecret
/// // Send result.ciphertext back to Alice (safe to send over any channel)
/// ```
///
/// **Step 3 — Alice decrypts the shared secret:**
/// ```swift
/// let aliceSharedSecret = try alicePrivateKey.decryptSharedSecret(ciphertext)
/// // aliceSharedSecret == bobSharedSecret
/// // Both parties now have identical shared secret bytes for symmetric encryption
/// ```
///
/// ## Saving and Loading Keys
///
/// ```swift
/// // Save
/// let privateKeyData = alicePrivateKey.rawRepresentation
/// let publicKeyData = alicePrivateKey.publicKey.rawRepresentation
///
/// // Load
/// let loaded = try HQC128.PrivateKey(
///     rawRepresentation: privateKeyData,
///     publicKeyRepresentation: publicKeyData
/// )
/// ```
public enum HQC128: Sendable {
    static let algorithmName = "HQC-128"

    /// A HQC128 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: HQC128.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: HQC128.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        /// Decrypts a shared secret from the given ciphertext.
        public func decryptSharedSecret(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: HQC128.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A HQC128 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: HQC128.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        /// Generates a new shared secret using this public key.
        public func generateSharedSecret() throws -> SharedSecretResult {
            let result = try kemEncapsulate(algorithm: HQC128.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
