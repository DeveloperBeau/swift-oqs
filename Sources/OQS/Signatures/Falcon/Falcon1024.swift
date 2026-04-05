import Foundation
internal import Cliboqs

/// Falcon-1024 digital signatures.
///
/// Falcon-1024 is a lattice-based signature scheme providing 256-bit security with compact signatures.
///
/// ## Signing and Verifying
///
/// **Step 1 — Alice generates a signing key and shares her public key:**
/// ```swift
/// let aliceSigningKey = try Falcon1024.PrivateKey()
/// let alicePublicKeyData = aliceSigningKey.publicKey.rawRepresentation
/// // Share alicePublicKeyData with anyone who needs to verify Alice's signatures
/// ```
///
/// **Step 2 — Alice signs a message:**
/// ```swift
/// let message = Data("Transfer $100 to Bob".utf8)
/// let signature = try aliceSigningKey.signature(for: message)
/// // Send both message and signature to the verifier
/// ```
///
/// **Step 3 — Bob verifies the signature using Alice's public key:**
/// ```swift
/// let alicePublicKey = try Falcon1024.PublicKey(rawRepresentation: alicePublicKeyData)
/// let isAuthentic = try alicePublicKey.isValidSignature(signature, for: message)
/// // isAuthentic == true means Alice signed this message
/// ```
///
/// ## Saving and Loading Keys
///
/// ```swift
/// // Save
/// let privateKeyData = aliceSigningKey.rawRepresentation
/// let publicKeyData = aliceSigningKey.publicKey.rawRepresentation
///
/// // Load
/// let loaded = try Falcon1024.PrivateKey(
///     rawRepresentation: privateKeyData,
///     publicKeyRepresentation: publicKeyData
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
