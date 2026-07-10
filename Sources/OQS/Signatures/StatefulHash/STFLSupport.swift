import Foundation
internal import Cliboqs

/// Build-mode information for the stateful signature schemes (XMSS/XMSSMT/LMS).
public enum StatefulSignatureSupport: Sendable {
    /// Whether this build of liboqs supports stateful-signature key generation
    /// and signing (a compile-time opt-in; enabled in this package's
    /// oqsconfig.h). Verification is always available regardless.
    public static var isKeyGenerationSupported: Bool {
        OQS_SIG_STFL_keygen_and_sign_supported() == 1
    }
}

/// Carries the user's persist closure and a caught-error slot across the C
/// store-callback boundary.
///
/// liboqs invokes the registered `store_cb` synchronously during signing, handing
/// it the freshly-advanced (serialized) secret-key state. We prepend the public
/// key so the blob the user persists is the same self-contained `pk || sk` format
/// that `serializedSecretKey` produces and `init(_:serializedSecretKey:)` consumes.
final class STFLStoreBox {
    let publicKey: Data
    let store: (Data) throws -> Void
    var caughtError: Error?

    init(publicKey: Data, _ store: @escaping (Data) throws -> Void) {
        self.publicKey = publicKey
        self.store = store
    }
}

/// Top-level, non-capturing C trampoline matching liboqs's `secure_store_sk`
/// signature: `OQS_STATUS (*)(uint8_t *sk_buf, size_t buf_len, void *context)`.
///
/// Returns `OQS_ERROR` when the user's closure throws (capturing the error in the
/// box); liboqs then makes `OQS_SIG_STFL_sign` fail, so the wrapper discards the
/// signature. This is what makes "signature returned IFF persisted" hold.
func stflStoreTrampoline(
    _ buf: UnsafeMutablePointer<UInt8>?,
    _ len: Int,
    _ ctx: UnsafeMutableRawPointer?
) -> OQS_STATUS {
    guard let ctx, let buf else { return OQS_ERROR }
    let box = Unmanaged<STFLStoreBox>.fromOpaque(ctx).takeUnretainedValue()
    do {
        try box.store(box.publicKey + Data(bytes: buf, count: len))
        return OQS_SUCCESS
    } catch {
        box.caughtError = error
        return OQS_ERROR
    }
}
