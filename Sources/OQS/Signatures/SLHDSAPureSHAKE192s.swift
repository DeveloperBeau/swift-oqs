import Foundation
internal import Cliboqs

/// SLH-DSA Pure SHAKE-192s digital signatures.
///
/// SLH-DSA (FIPS 205) is a NIST standard stateless hash-based signature scheme. This SHAKE-192s variant provides 192-bit security optimized for small signatures.
///
/// ## Usage
///
/// ```swift
/// // Generate a signing key
/// let signingKey = try SLHDSAPureSHAKE192s.PrivateKey()
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
/// let imported = try SLHDSAPureSHAKE192s.PrivateKey(
///     rawRepresentation: keyData,
///     publicKeyRepresentation: pubData
/// )
/// ```
public enum SLHDSAPureSHAKE192s: Sendable {
    static let algorithmName = "SLH_DSA_PURE_SHAKE_192S"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: SLHDSAPureSHAKE192s.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SLHDSAPureSHAKE192s.algorithmName)
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
            try sigSign(algorithm: SLHDSAPureSHAKE192s.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SLHDSAPureSHAKE192s.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: SLHDSAPureSHAKE192s.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
