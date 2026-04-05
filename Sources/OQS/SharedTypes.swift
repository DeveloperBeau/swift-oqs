import Foundation

public struct SharedSecret: Sendable, Equatable {
    public let rawRepresentation: Data

    public init(rawRepresentation: Data) {
        self.rawRepresentation = rawRepresentation
    }
}

public struct EncapsulationResult: Sendable {
    public let sharedSecret: SharedSecret
    public let ciphertext: Data
}
