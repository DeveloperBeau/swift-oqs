import Foundation
internal import Cliboqs

public enum HQC128: Sendable {
    static let algorithmName = "HQC-128"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: HQC128.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

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

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: HQC128.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

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

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: HQC128.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

public enum HQC192: Sendable {
    static let algorithmName = "HQC-192"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: HQC192.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

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

        public func decapsulate(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: HQC192.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

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

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: HQC192.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}

public enum HQC256: Sendable {
    static let algorithmName = "HQC-256"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: HQC256.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: HQC256.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: HQC256.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: HQC256.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func encapsulate() throws -> EncapsulationResult {
            let result = try kemEncapsulate(algorithm: HQC256.algorithmName, publicKey: rawRepresentation)
            return EncapsulationResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
