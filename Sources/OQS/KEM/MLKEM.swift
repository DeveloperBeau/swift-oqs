import Foundation
internal import Cliboqs

/// ML-KEM-512 key encapsulation.
public enum MLKEM512: Sendable {
    static let algorithmName = "ML-KEM-512"

    /// A ML-KEM-512 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM512.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM512.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: MLKEM512.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A ML-KEM-512 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM512.algorithmName)
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
            let result = try kemEncapsulate(algorithm: MLKEM512.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

/// ML-KEM-768 key encapsulation.
public enum MLKEM768: Sendable {
    static let algorithmName = "ML-KEM-768"

    /// A ML-KEM-768 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM768.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM768.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: MLKEM768.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A ML-KEM-768 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM768.algorithmName)
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
            let result = try kemEncapsulate(algorithm: MLKEM768.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

/// ML-KEM-1024 key encapsulation.
public enum MLKEM1024: Sendable {
    static let algorithmName = "ML-KEM-1024"

    /// A ML-KEM-1024 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM1024.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM1024.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: MLKEM1024.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A ML-KEM-1024 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM1024.algorithmName)
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
            let result = try kemEncapsulate(algorithm: MLKEM1024.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
