import Foundation
internal import Cliboqs

/// Classic McEliece 348864 key encapsulation.
public enum ClassicMcEliece348864: Sendable {
    static let algorithmName = "Classic-McEliece-348864"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece348864.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece348864.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece348864.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece348864.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: ClassicMcEliece348864.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

/// Classic McEliece 460896 key encapsulation.
public enum ClassicMcEliece460896: Sendable {
    static let algorithmName = "Classic-McEliece-460896"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece460896.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece460896.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece460896.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece460896.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: ClassicMcEliece460896.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

/// Classic McEliece 6688128 key encapsulation.
public enum ClassicMcEliece6688128: Sendable {
    static let algorithmName = "Classic-McEliece-6688128"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece6688128.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece6688128.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece6688128.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece6688128.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: ClassicMcEliece6688128.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

/// Classic McEliece 6960119 key encapsulation.
public enum ClassicMcEliece6960119: Sendable {
    static let algorithmName = "Classic-McEliece-6960119"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece6960119.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

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

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece6960119.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

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

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: ClassicMcEliece6960119.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

/// Classic McEliece 8192128 key encapsulation.
public enum ClassicMcEliece8192128: Sendable {
    static let algorithmName = "Classic-McEliece-8192128"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece8192128.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

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

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece8192128.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

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

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: ClassicMcEliece8192128.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
