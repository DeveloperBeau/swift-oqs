import Testing
import Foundation
@testable import OQS

@Suite struct ConcurrencyTests {

    @Test("100 concurrent KEM key generations all succeed with unique keys")
    func concurrentKEMKeyGeneration() async throws {
        let keys = try await withThrowingTaskGroup(
            of: KEM.KeyPair.self,
            returning: [KEM.KeyPair].self
        ) { group in
            for _ in 0..<100 {
                group.addTask {
                    try KEM.generateKeyPair(algorithm: .mlkem768)
                }
            }
            var results: [KEM.KeyPair] = []
            for try await keyPair in group {
                results.append(keyPair)
            }
            return results
        }

        #expect(keys.count == 100)
        let uniquePublicKeys = Set(keys.map { $0.publicKey })
        #expect(uniquePublicKeys.count == 100)
    }

    @Test("100 concurrent encap/decap round-trips produce matching secrets")
    func concurrentEncapDecap() async throws {
        let keyPair = try KEM.generateKeyPair(algorithm: .mlkem768)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<100 {
                group.addTask {
                    let encap = try KEM.encapsulate(algorithm: .mlkem768, publicKey: keyPair.publicKey)
                    let decapped = try KEM.decapsulate(
                        algorithm: .mlkem768,
                        ciphertext: encap.ciphertext,
                        secretKey: keyPair.secretKey
                    )
                    #expect(decapped == encap.sharedSecret)
                }
            }
            try await group.waitForAll()
        }
    }

    @Test("50 concurrent sign/verify operations all succeed")
    func concurrentSignVerify() async throws {
        let keyPair = try Signature.generateKeyPair(algorithm: .falcon512)
        let message = Data("Concurrent post-quantum signing test.".utf8)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    let sig = try Signature.sign(
                        algorithm: .falcon512,
                        message: message,
                        secretKey: keyPair.secretKey
                    )
                    let valid = try Signature.verify(
                        algorithm: .falcon512,
                        message: message,
                        signature: sig,
                        publicKey: keyPair.publicKey
                    )
                    #expect(valid)
                }
            }
            try await group.waitForAll()
        }
    }
}
