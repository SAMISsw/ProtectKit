// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "ProtectKit",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "ProtectKit",
            targets: ["ProtectKit"]),
    ],
    targets: [
        .target(
            name: "ProtectKit",
            dependencies: []),
        .testTarget(
            name: "ProtectKitTests",
            dependencies: ["ProtectKit"]),
    ]
)
