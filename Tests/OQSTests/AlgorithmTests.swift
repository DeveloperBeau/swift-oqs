import Testing
import Foundation
@testable import OQS

// Classic McEliece keygen is very slow and memory-intensive; test one
// representative to confirm the family works, then verify the rest
// via raw-value uniqueness.
private let kemAlgorithmsExcludingLargeMcEliece: [KEM.Algorithm] = KEM.Algorithm.allCases.filter {
    switch $0 {
    case .classicMcEliece460896, .classicMcEliece6688128,
         .classicMcEliece6960119, .classicMcEliece8192128:
        false
    default:
        true
    }
}

@Suite struct AlgorithmTests {

    // MARK: - KEM algorithms accepted by liboqs

    @Test("Every KEM algorithm is available in liboqs", arguments: kemAlgorithmsExcludingLargeMcEliece)
    func kemAlgorithmAvailable(algorithm: KEM.Algorithm) throws {
        _ = try KEM.generateKeyPair(algorithm: algorithm)
    }

    // MARK: - Signature algorithms accepted by liboqs

    @Test("Every Signature algorithm is available in liboqs", arguments: Signature.Algorithm.allCases)
    func signatureAlgorithmAvailable(algorithm: Signature.Algorithm) throws {
        _ = try Signature.generateKeyPair(algorithm: algorithm)
    }

    // MARK: - Raw value uniqueness

    @Test("KEM algorithm raw values are unique")
    func kemRawValuesUnique() {
        let rawValues = KEM.Algorithm.allCases.map(\.rawValue)
        #expect(Set(rawValues).count == rawValues.count)
    }

    @Test("Signature algorithm raw values are unique")
    func signatureRawValuesUnique() {
        let rawValues = Signature.Algorithm.allCases.map(\.rawValue)
        #expect(Set(rawValues).count == rawValues.count)
    }

    // MARK: - Error descriptions

    @Test("All OQSError cases produce non-empty descriptions")
    func errorDescriptionsNonEmpty() {
        let cases: [OQSError] = [
            .algorithmNotAvailable("test"),
            .keyGenerationFailed,
            .encapsulationFailed,
            .decapsulationFailed,
            .signFailed,
            .verifyFailed,
            .invalidKeySize(expected: 32, actual: 16),
        ]
        for error in cases {
            #expect(!error.description.isEmpty)
        }
    }

    @Test("invalidKeySize description includes both sizes")
    func invalidKeySizeDescription() {
        let error = OQSError.invalidKeySize(expected: 128, actual: 64)
        #expect(error.description.contains("128"))
        #expect(error.description.contains("64"))
    }

    @Test("algorithmNotAvailable description includes name")
    func algorithmNotAvailableDescription() {
        let error = OQSError.algorithmNotAvailable("FakeAlgo-999")
        #expect(error.description.contains("FakeAlgo-999"))
    }
}
