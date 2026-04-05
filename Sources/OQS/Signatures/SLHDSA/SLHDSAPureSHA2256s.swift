import Foundation
internal import Cliboqs

/// SLH-DSA Pure SHA2-256s digital signatures.
///
/// SLH-DSA (FIPS 205) is a NIST standard stateless hash-based signature scheme. This SHA2-256s variant provides 256-bit security optimized for small signatures.
///
/// ## Signing and Verifying
///
/// **Step 1 — Alice generates a signing key and shares her public key:**
/// ```swift
/// let aliceSigningKey = try SLHDSAPureSHA2256s.PrivateKey()
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
/// let alicePublicKey = try SLHDSAPureSHA2256s.PublicKey(rawRepresentation: alicePublicKeyData)
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
/// let loaded = try SLHDSAPureSHA2256s.PrivateKey(
///     rawRepresentation: privateKeyData,
///     publicKeyRepresentation: publicKeyData
/// )
/// ```
public enum SLHDSAPureSHA2256s: Sendable {
    static let algorithmName = "SLH_DSA_PURE_SHA2_256S"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: SLHDSAPureSHA2256s.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SLHDSAPureSHA2256s.algorithmName)
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
            try sigSign(algorithm: SLHDSAPureSHA2256s.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SLHDSAPureSHA2256s.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: SLHDSAPureSHA2256s.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
