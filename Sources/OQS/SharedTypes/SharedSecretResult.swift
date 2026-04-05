import Foundation

/// The result of generating a shared secret from a public key.
///
/// Contains the shared secret (which you keep) and the ciphertext
/// (which you send to the other party so they can decrypt the same secret).
public struct SharedSecretResult: Sendable {
    /// The shared secret that was generated.
    public let sharedSecret: SharedSecret
    /// The ciphertext to send to the private key holder for decryption.
    public let ciphertext: Data
}
