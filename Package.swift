import PackageDescription
let package = Package(
    name: "ProtectKit",
    platforms: [
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "ProtectKit",
            targets: ["ProtectKit"]
        ),
    ],
    targets: [
        .target(
            name: "ProtectKit",
            dependencies: []
        ),
        .testTarget(
            name: "ProtectKitTests",
            dependencies: ["ProtectKit"]
        ),
    ]
)
