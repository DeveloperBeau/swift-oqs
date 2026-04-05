import Foundation
internal import Cliboqs

/// Classic McEliece 6960119 key encapsulation.
///
/// Classic McEliece 6960119 is a conservative, code-based KEM with long-standing security assumptions and very large public keys. It targets 256-bit security with a different parameter trade-off.
///
/// ## Establishing a Shared Secret
///
/// Two parties (Alice and Bob) establish a shared secret without transmitting it directly.
///
/// **Step 1 — Alice generates a key pair and shares her public key:**
/// ```swift
/// let alicePrivateKey = try ClassicMcEliece6960119.PrivateKey()
/// let alicePublicKeyData = alicePrivateKey.publicKey.rawRepresentation
/// // Send alicePublicKeyData to Bob (this is safe to share publicly)
/// ```
///
/// **Step 2 — Bob receives Alice's public key and generates a shared secret:**
/// ```swift
/// let alicePublicKey = try ClassicMcEliece6960119.PublicKey(rawRepresentation: alicePublicKeyData)
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
/// let loaded = try ClassicMcEliece6960119.PrivateKey(
///     rawRepresentation: privateKeyData,
///     publicKeyRepresentation: publicKeyData
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

        /// Decrypts a shared secret from the given ciphertext.
        public func decryptSharedSecret(_ ciphertext: Data) throws -> SharedSecret {
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

        /// Generates a new shared secret using this public key.
        public func generateSharedSecret() throws -> SharedSecretResult {
            let result = try kemEncapsulate(algorithm: ClassicMcEliece6960119.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
