import Foundation
internal import Cliboqs

public enum Signature: Sendable {

    public enum Algorithm: String, CaseIterable, Sendable {
        // Falcon
        case falcon512 = "Falcon-512"
        case falcon1024 = "Falcon-1024"
        case falconPadded512 = "Falcon-padded-512"
        case falconPadded1024 = "Falcon-padded-1024"

        // SPHINCS+
        case sphincsSHA2128fSimple = "SPHINCS+-SHA2-128f-simple"
        case sphincsSHA2128sSimple = "SPHINCS+-SHA2-128s-simple"
        case sphincsSHA2192fSimple = "SPHINCS+-SHA2-192f-simple"
        case sphincsSHA2192sSimple = "SPHINCS+-SHA2-192s-simple"
        case sphincsSHA2256fSimple = "SPHINCS+-SHA2-256f-simple"
        case sphincsSHA2256sSimple = "SPHINCS+-SHA2-256s-simple"
        case sphincsSHAKE128fSimple = "SPHINCS+-SHAKE-128f-simple"
        case sphincsSHAKE128sSimple = "SPHINCS+-SHAKE-128s-simple"
        case sphincsSHAKE192fSimple = "SPHINCS+-SHAKE-192f-simple"
        case sphincsSHAKE192sSimple = "SPHINCS+-SHAKE-192s-simple"
        case sphincsSHAKE256fSimple = "SPHINCS+-SHAKE-256f-simple"
        case sphincsSHAKE256sSimple = "SPHINCS+-SHAKE-256s-simple"

        // CROSS
        case crossRSDP128Balanced = "cross-rsdp-128-balanced"
        case crossRSDP128Fast = "cross-rsdp-128-fast"
        case crossRSDP128Small = "cross-rsdp-128-small"
        case crossRSDP192Balanced = "cross-rsdp-192-balanced"
        case crossRSDP192Fast = "cross-rsdp-192-fast"
        case crossRSDP192Small = "cross-rsdp-192-small"
        case crossRSDP256Balanced = "cross-rsdp-256-balanced"
        case crossRSDP256Fast = "cross-rsdp-256-fast"
        case crossRSDP256Small = "cross-rsdp-256-small"
        case crossRSDPG128Balanced = "cross-rsdpg-128-balanced"
        case crossRSDPG128Fast = "cross-rsdpg-128-fast"
        case crossRSDPG128Small = "cross-rsdpg-128-small"
        case crossRSDPG192Balanced = "cross-rsdpg-192-balanced"
        case crossRSDPG192Fast = "cross-rsdpg-192-fast"
        case crossRSDPG192Small = "cross-rsdpg-192-small"
        case crossRSDPG256Balanced = "cross-rsdpg-256-balanced"
        case crossRSDPG256Fast = "cross-rsdpg-256-fast"
        case crossRSDPG256Small = "cross-rsdpg-256-small"

        // SLH-DSA (pure variants)
        case slhDSAPureSHA2128s = "SLH_DSA_PURE_SHA2_128S"
        case slhDSAPureSHA2128f = "SLH_DSA_PURE_SHA2_128F"
        case slhDSAPureSHA2192s = "SLH_DSA_PURE_SHA2_192S"
        case slhDSAPureSHA2192f = "SLH_DSA_PURE_SHA2_192F"
        case slhDSAPureSHA2256s = "SLH_DSA_PURE_SHA2_256S"
        case slhDSAPureSHA2256f = "SLH_DSA_PURE_SHA2_256F"
        case slhDSAPureSHAKE128s = "SLH_DSA_PURE_SHAKE_128S"
        case slhDSAPureSHAKE128f = "SLH_DSA_PURE_SHAKE_128F"
        case slhDSAPureSHAKE192s = "SLH_DSA_PURE_SHAKE_192S"
        case slhDSAPureSHAKE192f = "SLH_DSA_PURE_SHAKE_192F"
        case slhDSAPureSHAKE256s = "SLH_DSA_PURE_SHAKE_256S"
        case slhDSAPureSHAKE256f = "SLH_DSA_PURE_SHAKE_256F"
    }

    public struct KeyPair: Sendable {
        public let publicKey: Data
        public let secretKey: Data
    }

    public static func generateKeyPair(algorithm: Algorithm) throws -> KeyPair {
        ensureInitialized()

        guard let sig = OQS_SIG_new(algorithm.rawValue) else {
            throw OQSError.algorithmNotAvailable(algorithm.rawValue)
        }
        defer { OQS_SIG_free(sig) }

        let pkLen = Int(sig.pointee.length_public_key)
        let skLen = Int(sig.pointee.length_secret_key)
        var publicKey = Data(count: pkLen)
        var secretKey = Data(count: skLen)

        let rc = publicKey.withUnsafeMutableBytes { pk in
            secretKey.withUnsafeMutableBytes { sk in
                OQS_SIG_keypair(sig,
                    pk.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }

        return KeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public static func sign(
        algorithm: Algorithm,
        message: Data,
        secretKey: Data
    ) throws -> Data {
        ensureInitialized()

        guard let sig = OQS_SIG_new(algorithm.rawValue) else {
            throw OQSError.algorithmNotAvailable(algorithm.rawValue)
        }
        defer { OQS_SIG_free(sig) }

        let expectedSK = Int(sig.pointee.length_secret_key)
        guard secretKey.count == expectedSK else {
            throw OQSError.invalidKeySize(expected: expectedSK, actual: secretKey.count)
        }

        let maxSigLen = Int(sig.pointee.length_signature)
        var signature = Data(count: maxSigLen)
        var actualSigLen = 0

        let rc = message.withUnsafeBytes { msg in
            secretKey.withUnsafeBytes { sk in
                signature.withUnsafeMutableBytes { sigBuf in
                    OQS_SIG_sign(sig,
                        sigBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        &actualSigLen,
                        msg.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        message.count,
                        sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.signFailed }

        signature.removeSubrange(actualSigLen...)
        return signature
    }

    public static func verify(
        algorithm: Algorithm,
        message: Data,
        signature: Data,
        publicKey: Data
    ) throws -> Bool {
        ensureInitialized()

        guard let sig = OQS_SIG_new(algorithm.rawValue) else {
            throw OQSError.algorithmNotAvailable(algorithm.rawValue)
        }
        defer { OQS_SIG_free(sig) }

        let expectedPK = Int(sig.pointee.length_public_key)
        guard publicKey.count == expectedPK else {
            throw OQSError.invalidKeySize(expected: expectedPK, actual: publicKey.count)
        }

        let rc = message.withUnsafeBytes { msg in
            signature.withUnsafeBytes { sigBuf in
                publicKey.withUnsafeBytes { pk in
                    OQS_SIG_verify(sig,
                        msg.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        message.count,
                        sigBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        signature.count,
                        pk.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }

        return rc == OQS_SUCCESS
    }
}
