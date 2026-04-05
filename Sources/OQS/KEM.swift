import Foundation
internal import Cliboqs

public enum KEM: Sendable {

    public enum Algorithm: String, CaseIterable, Sendable {
        case mlkem512 = "ML-KEM-512"
        case mlkem768 = "ML-KEM-768"
        case mlkem1024 = "ML-KEM-1024"
        case bikeL1 = "BIKE-L1"
        case bikeL3 = "BIKE-L3"
        case bikeL5 = "BIKE-L5"
        case classicMcEliece348864 = "Classic-McEliece-348864"
        case classicMcEliece460896 = "Classic-McEliece-460896"
        case classicMcEliece6688128 = "Classic-McEliece-6688128"
        case classicMcEliece6960119 = "Classic-McEliece-6960119"
        case classicMcEliece8192128 = "Classic-McEliece-8192128"
        case hqc128 = "HQC-128"
        case hqc192 = "HQC-192"
        case hqc256 = "HQC-256"
    }

    public struct KeyPair: Sendable {
        public let publicKey: Data
        public let secretKey: Data
    }

    public struct EncapsulationResult: Sendable {
        public let ciphertext: Data
        public let sharedSecret: Data
    }

    public static func generateKeyPair(algorithm: Algorithm) throws -> KeyPair {
        ensureInitialized()

        guard let kem = OQS_KEM_new(algorithm.rawValue) else {
            throw OQSError.algorithmNotAvailable(algorithm.rawValue)
        }
        defer { OQS_KEM_free(kem) }

        let pkLen = Int(kem.pointee.length_public_key)
        let skLen = Int(kem.pointee.length_secret_key)
        var publicKey = Data(count: pkLen)
        var secretKey = Data(count: skLen)

        let rc = publicKey.withUnsafeMutableBytes { pk in
            secretKey.withUnsafeMutableBytes { sk in
                OQS_KEM_keypair(kem,
                    pk.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }

        return KeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public static func encapsulate(algorithm: Algorithm, publicKey: Data) throws -> EncapsulationResult {
        ensureInitialized()

        guard let kem = OQS_KEM_new(algorithm.rawValue) else {
            throw OQSError.algorithmNotAvailable(algorithm.rawValue)
        }
        defer { OQS_KEM_free(kem) }

        let expectedPK = Int(kem.pointee.length_public_key)
        guard publicKey.count == expectedPK else {
            throw OQSError.invalidKeySize(expected: expectedPK, actual: publicKey.count)
        }

        let ctLen = Int(kem.pointee.length_ciphertext)
        let ssLen = Int(kem.pointee.length_shared_secret)
        var ciphertext = Data(count: ctLen)
        var sharedSecret = Data(count: ssLen)

        let rc = publicKey.withUnsafeBytes { pk in
            ciphertext.withUnsafeMutableBytes { ct in
                sharedSecret.withUnsafeMutableBytes { ss in
                    OQS_KEM_encaps(kem,
                        ct.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ss.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        pk.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.encapsulationFailed }

        return EncapsulationResult(ciphertext: ciphertext, sharedSecret: sharedSecret)
    }

    public static func decapsulate(algorithm: Algorithm, ciphertext: Data, secretKey: Data) throws -> Data {
        ensureInitialized()

        guard let kem = OQS_KEM_new(algorithm.rawValue) else {
            throw OQSError.algorithmNotAvailable(algorithm.rawValue)
        }
        defer { OQS_KEM_free(kem) }

        let expectedSK = Int(kem.pointee.length_secret_key)
        guard secretKey.count == expectedSK else {
            throw OQSError.invalidKeySize(expected: expectedSK, actual: secretKey.count)
        }
        let expectedCT = Int(kem.pointee.length_ciphertext)
        guard ciphertext.count == expectedCT else {
            throw OQSError.invalidKeySize(expected: expectedCT, actual: ciphertext.count)
        }

        let ssLen = Int(kem.pointee.length_shared_secret)
        var sharedSecret = Data(count: ssLen)

        let rc = ciphertext.withUnsafeBytes { ct in
            secretKey.withUnsafeBytes { sk in
                sharedSecret.withUnsafeMutableBytes { ss in
                    OQS_KEM_decaps(kem,
                        ss.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ct.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.decapsulationFailed }

        return sharedSecret
    }
}
