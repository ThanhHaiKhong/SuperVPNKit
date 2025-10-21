// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SuperVPNKit",
    platforms: [
        .iOS(.v15), .macOS(.v14)
    ],
    products: [
		.singleTargetLibrary("SuperVPNKit"),
		.singleTargetLibrary("SuperVPNKitAppExtension"),
    ],
    dependencies: [
		.package(url: "https://github.com/ThanhHaiKhong/TunnelKit.git", branch: "master"),
		.package(url: "https://github.com/ThanhHaiKhong/VpnCoreKit.git", branch: "master"),
    ],
    targets: [
        .target(
            name: "SuperVPNKit",
            dependencies: [
                "VpnCoreKit",
                .product(name: "TunnelKitOpenVPN", package: "TunnelKit")
            ]
        ),
        .target(
            name: "SuperVPNKitAppExtension",
            dependencies: [
                .product(name: "TunnelKitOpenVPNAppExtension", package: "TunnelKit")
            ]
        ),
        .testTarget(
            name: "SuperVPNKitTests",
            dependencies: [
				"SuperVPNKit"
			]
		),
    ]
)

extension Product {
	static func singleTargetLibrary(_ name: String) -> Product {
		.library(name: name, targets: [name])
	}
}
