// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "swift-oqs",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "OQS", targets: ["OQS"]),
    ],
    targets: [
        .target(
            name: "Cliboqs",
            path: "Sources/Cliboqs",
            publicHeadersPath: "include",
            cSettings: [
                .define("OQS_DIST_BUILD", to: "1"),
                .define("OQS_USE_OPENSSL", to: "0"),
                .headerSearchPath("src"),
                .headerSearchPath("src/common"),
                .headerSearchPath("include"),
            ]
        ),
        .target(
            name: "OQS",
            dependencies: ["Cliboqs"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableExperimentalFeature("AccessLevelOnImport"),
            ]
        ),
        .testTarget(
            name: "OQSTests",
            dependencies: ["OQS"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
    ]
)
