import Testing
import Foundation
@testable import OQS

// Fast algorithms for detailed tests.
private let fastAlgorithms: [Signature.Algorithm] = [
    .falcon512, .falcon1024, .falconPadded512, .falconPadded1024,
    .crossRSDP128Fast,
]

// Slower algorithms - only used in the round-trip sweep.
private let slowAlgorithms: [Signature.Algorithm] = [
    .sphincsSHA2128fSimple, .sphincsSHA2256fSimple,
    .slhDSAPureSHA2128f, .slhDSAPureSHAKE128f,
]

private let testMessage = Data("Post-quantum cryptography is fun.".utf8)

@Suite struct SignatureTests {

    // MARK: - Round-trip

    @Test("Round-trip sign/verify", arguments: fastAlgorithms)
    func roundTrip(algorithm: Signature.Algorithm) throws {
        let keyPair = try Signature.generateKeyPair(algorithm: algorithm)
        let sig = try Signature.sign(algorithm: algorithm, message: testMessage, secretKey: keyPair.secretKey)
        let valid = try Signature.verify(algorithm: algorithm, message: testMessage, signature: sig, publicKey: keyPair.publicKey)
        #expect(valid)
    }

    @Test("Round-trip slow algorithms", arguments: slowAlgorithms)
    func roundTripSlow(algorithm: Signature.Algorithm) throws {
        let keyPair = try Signature.generateKeyPair(algorithm: algorithm)
        let sig = try Signature.sign(algorithm: algorithm, message: testMessage, secretKey: keyPair.secretKey)
        let valid = try Signature.verify(algorithm: algorithm, message: testMessage, signature: sig, publicKey: keyPair.publicKey)
        #expect(valid)
    }

    @Test("Sign and verify empty message")
    func emptyMessage() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig = try Signature.sign(algorithm: .falcon512, message: Data(), secretKey: keyPair.secretKey)
        let valid = try Signature.verify(algorithm: .falcon512, message: Data(), signature: sig, publicKey: keyPair.publicKey)
        #expect(valid)
    }

    // MARK: - Key uniqueness

    @Test("Key pairs are unique")
    func keyPairUniqueness() throws {
        let a = try Signature.generateKeyPair(algorithm: .falcon512)
        let b = try Signature.generateKeyPair(algorithm: .falcon512)
        #expect(a.publicKey != b.publicKey)
        #expect(a.secretKey != b.secretKey)
    }

    // MARK: - Failure: wrong message

    @Test("Verify rejects wrong message")
    func wrongMessage() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        let wrong = Data("Wrong message.".utf8)
        let valid = try Signature.verify(algorithm: .falcon512, message: wrong, signature: sig, publicKey: keyPair.publicKey)
        #expect(!valid)
    }

    // MARK: - Failure: wrong public key

    @Test("Verify rejects wrong public key")
    func wrongPublicKey() throws {
        let keyPairA = try Signature.generateKeyPair(algorithm: .falcon512)
        let keyPairB = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPairA.secretKey)
        let valid = try Signature.verify(algorithm: .falcon512, message: testMessage, signature: sig, publicKey: keyPairB.publicKey)
        #expect(!valid)
    }

    // MARK: - Failure: corrupted signature

    @Test("Verify rejects corrupted signature")
    func corruptedSignature() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        var sig = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        sig[sig.count / 2] ^= 0xFF
        let valid = try Signature.verify(algorithm: .falcon512, message: testMessage, signature: sig, publicKey: keyPair.publicKey)
        #expect(!valid)
    }

    // MARK: - Failure: truncated signature

    @Test("Verify rejects truncated signature")
    func truncatedSignature() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        let truncated = sig.prefix(sig.count / 2)
        let valid = try Signature.verify(algorithm: .falcon512, message: testMessage, signature: truncated, publicKey: keyPair.publicKey)
        #expect(!valid)
    }

    // MARK: - Failure: invalid key sizes

    @Test("Sign rejects wrong secret key size")
    func signInvalidSecretKeySize() throws {
        #expect(throws: OQSError.self) {
            try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: Data([0x00]))
        }
    }

    @Test("Verify rejects wrong public key size")
    func verifyInvalidPublicKeySize() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        #expect(throws: OQSError.self) {
            try Signature.verify(algorithm: .falcon512, message: testMessage, signature: sig, publicKey: Data([0x00]))
        }
    }

    // MARK: - Failure: empty keys

    @Test("Sign rejects empty secret key")
    func signEmptySecretKey() throws {
        #expect(throws: OQSError.self) {
            try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: Data())
        }
    }

    @Test("Verify rejects empty public key")
    func verifyEmptyPublicKey() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        #expect(throws: OQSError.self) {
            try Signature.verify(algorithm: .falcon512, message: testMessage, signature: sig, publicKey: Data())
        }
    }

    // MARK: - Cross-algorithm mismatch

    @Test("Cross-algorithm keys are rejected")
    func crossAlgorithmMismatch() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        // falcon512 public key size != falcon1024 expected size
        #expect(throws: OQSError.self) {
            try Signature.verify(algorithm: .falcon1024, message: testMessage, signature: sig, publicKey: keyPair.publicKey)
        }
    }

    // MARK: - Boundary: multiple signatures differ

    @Test("Multiple signatures of same message differ")
    func multipleSignaturesDiffer() throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let sig1 = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        let sig2 = try Signature.sign(algorithm: .falcon512, message: testMessage, secretKey: keyPair.secretKey)
        #expect(sig1 != sig2)
        // Both should still verify
        #expect(try Signature.verify(algorithm: .falcon512, message: testMessage, signature: sig1, publicKey: keyPair.publicKey))
        #expect(try Signature.verify(algorithm: .falcon512, message: testMessage, signature: sig2, publicKey: keyPair.publicKey))
    }
}
