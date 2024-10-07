// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LagowareCapacitorKeyManager",
    platforms: [.iOS(.v13)],
    products: [
        .library(
            name: "LagowareCapacitorKeyManager",
            targets: ["KeyManagerPlugin"])
    ],
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", branch: "main")
    ],
    targets: [
        .target(
            name: "KeyManagerPlugin",
            dependencies: [
                .product(name: "Capacitor", package: "capacitor-swift-pm"),
                .product(name: "Cordova", package: "capacitor-swift-pm")
            ],
            path: "ios/Sources/KeyManagerPlugin"),
        .testTarget(
            name: "KeyManagerPluginTests",
            dependencies: ["KeyManagerPlugin"],
            path: "ios/Tests/KeyManagerPluginTests")
    ]
)