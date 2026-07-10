import Foundation

private final class ResultBox<T: Sendable>: @unchecked Sendable {
    var result: Result<T, any Error>?
    init() {}
}

/// Runs `body` on a dedicated thread with an 8 MB stack and blocks until it
/// finishes. Some algorithms (SNOVA rank-5, MAYO-5, MQOM2 signing) consume
/// hundreds of KB of C stack; swift-testing worker threads have 512 KB and
/// overflow with an uncatchable SIGBUS instead of a catchable error.
func onLargeStack<T: Sendable>(_ body: @escaping @Sendable () throws -> T) throws -> T {
    let box = ResultBox<T>()
    let sema = DispatchSemaphore(value: 0)
    let thread = Thread {
        box.result = Result { try body() }
        sema.signal()
    }
    thread.stackSize = 8 << 20
    thread.start()
    sema.wait()
    return try box.result!.get()
}
