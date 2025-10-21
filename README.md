# SuperVPNKit

A Swift library for creating VPN tunnels on iOS with support for multiple protocols.

## Features

- 🔒 Multiple VPN protocol support (OpenVPN, IKEv2)
- 🛠️ Easy-to-use helper functions for tunnel creation
- 📦 Protocol extensions for enhanced functionality
- 🧩 Modular design for easy integration
- 🔍 Comprehensive logging with OSLog

## Supported Protocols

- **OpenVPN** - Full support with XOR obfuscation
- **IKEv2** - Native iOS IKEv2 with EAP-MSCHAPv2
- **WireGuard** - Coming soon

## Installation

### Swift Package Manager

Add SuperVPNKit as a dependency to your `Package.swift`:

```swift
dependencies: [
    .package(path: "../SuperVPNKit")
]
```

Or add it locally in Xcode:
1. File → Add Packages
2. Choose "Add Local..."
3. Select the SuperVPNKit folder

## Usage

### Basic Setup

```swift
import SuperVPNKit
import VpnCoreKit

// Initialize VPN manager
let vpnManager = VPNManager(
    appGroup: "group.your.app.id",
    bundleIdentifier: "your.app.BundleId.NetworkExtension"
)

// Connect to a server
let config: VpnCoreKit.ServerConfiguration = // ... your config
await vpnManager.connect(with: config, protocolType: .openVPN)

// Disconnect
await vpnManager.disconnect()
```

### Using Helper Functions

```swift
import SuperVPNKit

// Create a tunnel directly
let provider = try await VPNTunnelHelper.createTunnel(
    with: serverConfig,
    protocolType: .ikev2,
    appGroup: "group.your.app.id",
    bundleIdentifier: "your.app.BundleId.NetworkExtension"
)

// Connect using the provider
try await provider.connect(with: serverConfig)

// Check current status
let status = await VPNTunnelHelper.getCurrentStatus()
print(status.displayText) // "Connected", "Disconnected", etc.

// Get saved configurations
let savedConfigs = try await VPNTunnelHelper.getSavedConfigurations()
```

### Protocol Extensions

```swift
import SuperVPNKit

// Check protocol support
let protocolType = VPNProtocolType.openVPN
if protocolType.isSupported {
    print("Protocol is supported: \(protocolType.displayName)")
}

// Check connection status
let status = VPNConnectionStatus.connected
if status.isActive {
    print("VPN is active")
}

// Get status color for UI
let color = status.statusColor
// Returns RGB tuple: (red: Double, green: Double, blue: Double)

// ServerConfiguration extensions
if serverConfig.supports(protocol: .openVPN) {
    let provider = try await serverConfig.createTunnel(
        with: .openVPN,
        appGroup: "group.your.app.id",
        bundleIdentifier: "your.app.BundleId.NetworkExtension"
    )
}
```

### ObservableObject Integration (SwiftUI)

```swift
import SwiftUI
import SuperVPNKit

@main
struct MyApp: App {
    @StateObject private var vpnManager = VPNManager(
        appGroup: "group.your.app.id",
        bundleIdentifier: "your.app.BundleId.NetworkExtension"
    )

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpnManager)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var vpnManager: VPNManager

    var body: some View {
        VStack {
            Text(vpnManager.statusMessage)

            Button(vpnManager.isConnected ? "Disconnect" : "Connect") {
                Task {
                    if vpnManager.isConnected {
                        await vpnManager.disconnect()
                    } else {
                        await vpnManager.connect(with: config, protocolType: .openVPN)
                    }
                }
            }
        }
    }
}
```

## Architecture

### Core Components

- **VPNManager**: Main interface for managing VPN connections
- **VPNProvider**: Protocol that all VPN implementations conform to
- **VPNTunnelHelper**: Static helper functions for tunnel operations
- **OpenVPNProvider**: OpenVPN implementation using TunnelKit
- **IKEv2Provider**: Native iOS IKEv2 implementation

### Protocol Extensions

The library includes extensions for:
- `VPNProtocolType` - Protocol identification and support checking
- `VPNConnectionStatus` - Status properties and UI helpers
- `ServerConfiguration` - Quick tunnel creation

## Requirements

- iOS 15.0+
- macOS 12.0+
- Swift 5.9+
- Xcode 15.0+

## Dependencies

- VpnCoreKit - API and configuration models
- TunnelKit - OpenVPN implementation

## Example

See the `SuperVPNExample` app for a complete working example.

## License

[Your License Here]
