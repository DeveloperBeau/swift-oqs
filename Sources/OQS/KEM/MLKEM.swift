import Foundation
internal import Cliboqs

public enum MLKEM512: Sendable {
    static let algorithmName = "ML-KEM-512"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM512.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

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

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: MLKEM512.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

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

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: MLKEM512.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

public enum MLKEM768: Sendable {
    static let algorithmName = "ML-KEM-768"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM768.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

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

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: MLKEM768.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

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

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: MLKEM768.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

public enum MLKEM1024: Sendable {
    static let algorithmName = "ML-KEM-1024"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM1024.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

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

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: MLKEM1024.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

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

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: MLKEM1024.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
