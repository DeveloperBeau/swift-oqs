internal import Cliboqs

private let _oqsInit: Void = {
    OQS_init()
}()

@inline(__always)
func ensureInitialized() {
    _ = _oqsInit
}
