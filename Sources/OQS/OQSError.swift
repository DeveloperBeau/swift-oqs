public enum OQSError: Error, Sendable, CustomStringConvertible {
    case algorithmNotAvailable(String)
    case keyGenerationFailed
    case encapsulationFailed
    case decapsulationFailed
    case signFailed
    case verifyFailed
    case invalidKeySize(expected: Int, actual: Int)

    public var description: String {
        switch self {
        case .algorithmNotAvailable(let name): "Algorithm not available: \(name)"
        case .keyGenerationFailed: "Key generation failed"
        case .encapsulationFailed: "KEM encapsulation failed"
        case .decapsulationFailed: "KEM decapsulation failed"
        case .signFailed: "Signature generation failed"
        case .verifyFailed: "Signature verification failed"
        case .invalidKeySize(let expected, let actual): "Invalid key size: expected \(expected) bytes, got \(actual)"
        }
    }
}
