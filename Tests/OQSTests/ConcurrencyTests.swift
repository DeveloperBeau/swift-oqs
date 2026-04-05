import Testing
import Foundation
@testable import OQS

@Suite struct ConcurrencyTests {

    @Test("100 concurrent KEM key generations all succeed with unique keys")
    func concurrentKEMKeyGeneration() async throws {
        let keys = try await withThrowingTaskGroup(
            of: MLKEM768.PrivateKey.self,
            returning: [MLKEM768.PrivateKey].self
        ) { group in
            for _ in 0..<100 {
                group.addTask {
                    try MLKEM768.PrivateKey()
                }
            }
            var results: [MLKEM768.PrivateKey] = []
            for try await key in group {
                results.append(key)
            }
            return results
        }

        #expect(keys.count == 100)
        let uniquePublicKeys = Set(keys.map { $0.publicKey.rawRepresentation })
        #expect(uniquePublicKeys.count == 100)
    }

    @Test("100 concurrent encap/decap round-trips produce matching secrets")
    func concurrentEncapDecap() async throws {
        let privateKey = try MLKEM768.PrivateKey()

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<100 {
                group.addTask {
                    let sealed = try privateKey.publicKey.encapsulate()
                    let secret = try privateKey.decapsulate(sealed.ciphertext)
                    #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
                }
            }
            try await group.waitForAll()
        }
    }

    @Test("50 concurrent sign/verify operations all succeed")
    func concurrentSignVerify() async throws {
        let signingKey = try Falcon512.PrivateKey()
        let message = Data("Concurrent post-quantum signing test.".utf8)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    let sig = try signingKey.signature(for: message)
                    let valid = try signingKey.publicKey.isValidSignature(sig, for: message)
                    #expect(valid)
                }
            }
            try await group.waitForAll()
        }
    }
}
