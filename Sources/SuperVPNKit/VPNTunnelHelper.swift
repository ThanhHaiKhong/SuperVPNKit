import Foundation
import NetworkExtension
import VpnCoreKit

// MARK: - VPN Tunnel Helper

/// Helper functions for creating and managing VPN tunnels
public enum VPNTunnelHelper {

    /// Create a VPN tunnel with the given configuration
    /// - Parameters:
    ///   - config: Server configuration from VpnCoreKit
    ///   - protocolType: VPN protocol type to use
    ///   - appGroup: App group identifier for shared data
    ///   - bundleIdentifier: Bundle identifier for the network extension
    /// - Returns: Configured VPN provider ready to connect
    public static func createTunnel(
        with config: VpnCoreKit.ServerConfiguration,
        protocolType: VPNProtocolType,
        appGroup: String,
        bundleIdentifier: String
    ) async throws -> VPNProvider {
        let provider: VPNProvider

        switch protocolType {
        case .openVPN:
            provider = OpenVPNProvider(appGroup: appGroup, bundleIdentifier: bundleIdentifier)
        case .ikev2:
            provider = IKEv2Provider()
        case .wireGuard:
            throw VPNError.connectionFailed("WireGuard not yet implemented")
        }

        try await provider.loadConfiguration()
        return provider
    }

    /// Get all saved VPN configurations
    /// - Returns: Array of saved VPN managers
    public static func getSavedConfigurations() async throws -> [NETunnelProviderManager] {
        return try await NETunnelProviderManager.loadAllFromPreferences()
    }

    /// Remove all saved VPN configurations
    public static func removeAllConfigurations() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        for manager in managers {
            try await manager.removeFromPreferences()
        }
    }

    /// Get current VPN connection status
    /// - Returns: Current VPN connection status
    public static func getCurrentStatus() async -> VPNConnectionStatus {
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
              let status = managers.first?.connection.status else {
            return .disconnected
        }
        return VPNConnectionStatus(from: status)
    }
}

// MARK: - Protocol Extensions

extension VPNProtocolType {
    /// Returns true if the protocol type is supported
    public var isSupported: Bool {
        switch self {
        case .openVPN, .ikev2:
            return true
        case .wireGuard:
            return false
        }
    }

    /// Returns the protocol identifier string
    public var identifier: String {
        switch self {
        case .openVPN:
            return "openvpn"
        case .ikev2:
            return "ikev2"
        case .wireGuard:
            return "wireguard"
        }
    }
}

extension VPNConnectionStatus {
    /// Returns true if the status represents an active connection
    public var isActive: Bool {
        switch self {
        case .connected, .connecting, .reasserting:
            return true
        case .disconnected, .disconnecting, .invalid:
            return false
        }
    }

    /// Returns the color representation for UI
    public var statusColor: (red: Double, green: Double, blue: Double) {
        switch self {
        case .connected:
            return (0.0, 1.0, 0.0) // Green
        case .connecting, .reasserting:
            return (1.0, 0.647, 0.0) // Orange
        case .disconnected, .disconnecting:
            return (0.5, 0.5, 0.5) // Gray
        case .invalid:
            return (1.0, 0.0, 0.0) // Red
        }
    }
}

// MARK: - ServerConfiguration Extensions

extension VpnCoreKit.ServerConfiguration {
    /// Returns true if the server supports the given protocol type
    public func supports(protocol protocolType: VPNProtocolType) -> Bool {
        // Check if the server's protocol matches the requested protocol
        switch protocolType {
        case .openVPN:
            return self.protocol == .openvpn
        case .ikev2:
            return self.protocol == .ikev2
        case .wireGuard:
            return false // Not yet supported
        }
    }

    /// Quick tunnel creation helper
    public func createTunnel(
        with protocolType: VPNProtocolType,
        appGroup: String,
        bundleIdentifier: String
    ) async throws -> VPNProvider {
        return try await VPNTunnelHelper.createTunnel(
            with: self,
            protocolType: protocolType,
            appGroup: appGroup,
            bundleIdentifier: bundleIdentifier
        )
    }
}
