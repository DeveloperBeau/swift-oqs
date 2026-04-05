import Foundation

/// A shared secret established through key encapsulation.
public struct SharedSecret: Sendable, Equatable {
    /// The raw secret bytes.
    public let rawRepresentation: Data

    /// Creates a shared secret from raw bytes.
    public init(rawRepresentation: Data) {
        self.rawRepresentation = rawRepresentation
    }
}

/// The result of a KEM encapsulation operation, containing both the shared secret and the ciphertext.
public struct EncapsulationResult: Sendable {
    /// The shared secret established by encapsulation.
    public let sharedSecret: SharedSecret
    /// The ciphertext to send to the private key holder for decapsulation.
    public let ciphertext: Data
}
