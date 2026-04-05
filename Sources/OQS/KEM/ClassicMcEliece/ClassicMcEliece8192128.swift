import Foundation
internal import Cliboqs

/// Classic McEliece 8192128 key encapsulation.
///
/// Classic McEliece 8192128 is the largest Classic McEliece parameter set, offering the highest security margin among the conservative, code-based KEM variants.
///
/// ## Establishing a Shared Secret
///
/// Two parties (Alice and Bob) establish a shared secret without transmitting it directly.
///
/// **Step 1 — Alice generates a key pair and shares her public key:**
/// ```swift
/// let alicePrivateKey = try ClassicMcEliece8192128.PrivateKey()
/// let alicePublicKeyData = alicePrivateKey.publicKey.rawRepresentation
/// // Send alicePublicKeyData to Bob (this is safe to share publicly)
/// ```
///
/// **Step 2 — Bob receives Alice's public key and generates a shared secret:**
/// ```swift
/// let alicePublicKey = try ClassicMcEliece8192128.PublicKey(rawRepresentation: alicePublicKeyData)
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
/// ## Using the Shared Secret
///
/// The shared secret is a cryptographic key that both parties now hold. Common uses:
///
/// - **Encrypt messages** — Use it as an AES-GCM or ChaCha20 key to encrypt data between the parties.
/// - **Derive multiple keys** — Feed it into a key derivation function (like HKDF) to create
///   separate keys for encryption, authentication, etc.
/// - **Establish a secure channel** — Use it as the session key for an encrypted communication protocol.
///
/// ```swift
/// // Example: Use the shared secret as an AES-GCM key
/// let symmetricKey = SymmetricKey(data: sharedSecret.rawRepresentation)
/// let encrypted = try AES.GCM.seal(plaintext, using: symmetricKey)
/// ```
///
/// > The shared secret should be used immediately or stored securely.
/// > Never transmit it — the entire point of key encapsulation is that
/// > both parties derive it independently.
///
/// ## Saving and Loading Keys
///
/// ```swift
/// // Save
/// let privateKeyData = alicePrivateKey.rawRepresentation
/// let publicKeyData = alicePrivateKey.publicKey.rawRepresentation
///
/// // Load
/// let loaded = try ClassicMcEliece8192128.PrivateKey(
///     rawRepresentation: privateKeyData,
///     publicKeyRepresentation: publicKeyData
/// )
/// ```
public enum ClassicMcEliece8192128: Sendable {
    static let algorithmName = "Classic-McEliece-8192128"

    /// A ClassicMcEliece8192128 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece8192128.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece8192128.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece8192128.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A ClassicMcEliece8192128 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece8192128.algorithmName)
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
            let result = try kemEncapsulate(algorithm: ClassicMcEliece8192128.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
