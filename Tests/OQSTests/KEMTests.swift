import Testing
import Foundation
@testable import OQS

// Algorithms that are fast enough to run detailed tests on.
private let fastAlgorithms: [KEM.Algorithm] = [
    .mlkem512, .mlkem768, .mlkem1024,
    .hqc128, .hqc192, .hqc256,
]

// Classic McEliece variants are very slow; only include in the full sweep.
private let slowAlgorithms: [KEM.Algorithm] = [
    .classicMcEliece348864,
    .classicMcEliece460896,
    .classicMcEliece6688128,
    .classicMcEliece6960119,
    .classicMcEliece8192128,
]

@Suite struct KEMTests {

    // MARK: - Round-trip

    @Test("Round-trip encap/decap", arguments: fastAlgorithms)
    func roundTrip(algorithm: KEM.Algorithm) throws {
        let keyPair = try KEM.generateKeyPair(algorithm: algorithm)
        let encap = try KEM.encapsulate(algorithm: algorithm, publicKey: keyPair.publicKey)
        let decapped = try KEM.decapsulate(algorithm: algorithm, ciphertext: encap.ciphertext, secretKey: keyPair.secretKey)
        #expect(decapped == encap.sharedSecret)
    }

    @Test("Round-trip Classic McEliece 348864")
    func roundTripMcEliece() throws {
        let alg = KEM.Algorithm.classicMcEliece348864
        let keyPair = try KEM.generateKeyPair(algorithm: alg)
        let encap = try KEM.encapsulate(algorithm: alg, publicKey: keyPair.publicKey)
        let decapped = try KEM.decapsulate(algorithm: alg, ciphertext: encap.ciphertext, secretKey: keyPair.secretKey)
        #expect(decapped == encap.sharedSecret)
    }

    // MARK: - Key pair uniqueness

    @Test("Key pairs are unique")
    func keyPairUniqueness() throws {
        let a = try KEM.generateKeyPair(algorithm: .mlkem768)
        let b = try KEM.generateKeyPair(algorithm: .mlkem768)
        #expect(a.publicKey != b.publicKey)
        #expect(a.secretKey != b.secretKey)
    }

    // MARK: - Multiple encapsulations produce different ciphertexts

    @Test("Multiple encapsulations differ")
    func multipleEncapsulations() throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)
        let first = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)
        let second = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)
        #expect(first.ciphertext != second.ciphertext)
        #expect(first.sharedSecret != second.sharedSecret)
    }

    // MARK: - Wrong secret key

    @Test("Decapsulate with wrong secret key", arguments: fastAlgorithms)
    func wrongSecretKey(algorithm: KEM.Algorithm) throws {
        let keyPairA = try KEM.generateKeyPair(algorithm: algorithm)
        let keyPairB = try KEM.generateKeyPair(algorithm: algorithm)
        let encap = try KEM.encapsulate(algorithm: algorithm, publicKey: keyPairA.publicKey)

        // liboqs may return a different secret or throw depending on algorithm
        do {
            let decapped = try KEM.decapsulate(algorithm: algorithm, ciphertext: encap.ciphertext, secretKey: keyPairB.secretKey)
            #expect(decapped != encap.sharedSecret)
        } catch {
            // acceptable: some algorithms throw on decapsulation failure
        }
    }

    // MARK: - Invalid key sizes

    @Test("Encapsulate rejects wrong public key size")
    func encapsulateInvalidPublicKeySize() throws {
        #expect(throws: OQSError.self) {
            try KEM.encapsulate(algorithm: .mlkem768, publicKey: Data([0x00]))
        }
    }

    @Test("Decapsulate rejects wrong secret key size")
    func decapsulateInvalidSecretKeySize() throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)
        let encap = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)
        #expect(throws: OQSError.self) {
            try KEM.decapsulate(algorithm: .mlkem768, ciphertext: encap.ciphertext, secretKey: Data([0x00]))
        }
    }

    @Test("Decapsulate rejects wrong ciphertext size")
    func decapsulateInvalidCiphertextSize() throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)
        #expect(throws: OQSError.self) {
            try KEM.decapsulate(algorithm: .mlkem768, ciphertext: Data([0x00]), secretKey: keyPair.secretKey)
        }
    }

    // MARK: - Empty inputs

    @Test("Encapsulate rejects empty public key")
    func encapsulateEmptyPublicKey() throws {
        #expect(throws: OQSError.self) {
            try KEM.encapsulate(algorithm: .mlkem768, publicKey: Data())
        }
    }

    @Test("Decapsulate rejects empty secret key")
    func decapsulateEmptySecretKey() throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)
        let encap = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)
        #expect(throws: OQSError.self) {
            try KEM.decapsulate(algorithm: .mlkem768, ciphertext: encap.ciphertext, secretKey: Data())
        }
    }

    @Test("Decapsulate rejects empty ciphertext")
    func decapsulateEmptyCiphertext() throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)
        #expect(throws: OQSError.self) {
            try KEM.decapsulate(algorithm: .mlkem768, ciphertext: Data(), secretKey: keyPair.secretKey)
        }
    }

    // MARK: - Cross-algorithm mismatch

    @Test("Cross-algorithm keys are rejected")
    func crossAlgorithmMismatch() throws {
        let keyPair512 = try KEM.generateKeyPair(algorithm: .mlkem512)
        // mlkem512 public key size != mlkem768 expected size
        #expect(throws: OQSError.self) {
            try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair512.publicKey)
        }
    }

    // MARK: - Truncated ciphertext

    @Test("Truncated ciphertext is rejected")
    func truncatedCiphertext() throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)
        let encap = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)
        let truncated = encap.ciphertext.prefix(encap.ciphertext.count - 1)
        #expect(throws: OQSError.self) {
            try KEM.decapsulate(algorithm: .mlkem768, ciphertext: truncated, secretKey: keyPair.secretKey)
        }
    }

    // MARK: - Extended ciphertext

    @Test("Extended ciphertext is rejected")
    func extendedCiphertext() throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)
        let encap = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)
        let extended = encap.ciphertext + Data([0x00])
        #expect(throws: OQSError.self) {
            try KEM.decapsulate(algorithm: .mlkem768, ciphertext: extended, secretKey: keyPair.secretKey)
        }
    }
}
