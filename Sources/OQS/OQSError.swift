/// Errors thrown by OQS cryptographic operations.
public enum OQSError: Error, Sendable, CustomStringConvertible {
    /// The requested algorithm is not available in the current build.
    case algorithmNotAvailable(String)
    /// Key pair generation failed.
    case keyGenerationFailed
    /// KEM encapsulation failed.
    case encapsulationFailed
    /// KEM decapsulation failed.
    case decapsulationFailed
    /// Signature generation failed.
    case signFailed
    /// Signature verification failed.
    case verifyFailed
    /// The provided key data has the wrong size.
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
