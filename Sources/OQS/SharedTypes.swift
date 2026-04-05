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

/// The result of generating a shared secret, containing both the secret and the ciphertext.
public struct SharedSecretResult: Sendable {
    /// The shared secret that was generated.
    public let sharedSecret: SharedSecret
    /// The ciphertext to send to the private key holder for decryption.
    public let ciphertext: Data
}
