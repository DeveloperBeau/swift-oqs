internal import Cliboqs

/// Ensures the liboqs C library is initialized before any operations run.
///
/// This runs automatically. You never need to call it yourself. The first time
/// any key generation, encapsulation, or signing operation runs, liboqs gets
/// initialized behind the scenes.
private let _oqsInit: Void = {
    OQS_init()
}()

@inline(__always)
func ensureInitialized() {
    _ = _oqsInit
}
