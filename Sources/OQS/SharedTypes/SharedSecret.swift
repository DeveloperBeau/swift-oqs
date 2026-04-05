import Foundation

/// A shared secret established between two parties via key encapsulation.
///
/// Both sides end up with the same bytes after a KEM exchange. Use
/// `rawRepresentation` to get the bytes for symmetric encryption.
public struct SharedSecret: Sendable, Equatable {
    /// The raw secret bytes.
    public let rawRepresentation: Data

    /// Creates a shared secret from raw bytes.
    public init(rawRepresentation: Data) {
        self.rawRepresentation = rawRepresentation
    }
}
