import Foundation
import NetworkExtension
import VpnCoreKit

// MARK: - VPN Provider Protocol

/// Protocol that all VPN providers must implement
public protocol VPNProvider {
    var protocolType: String { get }

    func connect(with config: VpnCoreKit.ServerConfiguration) async throws
    func disconnect() async throws
    func updateStatus(_ status: NEVPNStatus)
    func loadConfiguration() async throws
    func getConnection() -> NEVPNConnection?
    func getDataCount() -> (received: UInt64, sent: UInt64)?
}

// MARK: - VPN Provider Extensions

extension VPNProvider {
    /// Get current data count (bytes sent/received)
    /// Default implementation returns nil, override in specific providers
    public func getDataCount() -> (received: UInt64, sent: UInt64)? {
        print("⚠️ [VPNProvider] DEFAULT getDataCount() called - this means OpenVPNProvider override is NOT being used!")
        print("⚠️ [VPNProvider] Type: \(type(of: self))")
        return nil
    }
}

// MARK: - VPN Status

/// Connection status for VPN
public enum VPNConnectionStatus: Equatable {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case reasserting
    case invalid

    public init(from status: NEVPNStatus) {
        switch status {
        case .connected:
            self = .connected
        case .connecting:
            self = .connecting
        case .disconnected:
            self = .disconnected
        case .disconnecting:
            self = .disconnecting
        case .reasserting:
            self = .reasserting
        case .invalid:
            self = .invalid
        @unknown default:
            self = .invalid
        }
    }

    public var displayText: String {
        switch self {
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting..."
        case .connected:
            return "Connected"
        case .disconnecting:
            return "Disconnecting..."
        case .reasserting:
            return "Reconnecting..."
        case .invalid:
            return "Invalid Configuration"
        }
    }
}

// MARK: - VPN Protocol Types

public enum VPNProtocolType {
    case openVPN
    case ikev2
    case wireGuard

    public var displayName: String {
        switch self {
        case .openVPN:
            return "OpenVPN"
        case .ikev2:
            return "IKEv2"
        case .wireGuard:
            return "WireGuard"
        }
    }
}

// MARK: - VPN Error

public enum VPNError: LocalizedError {
    case configurationNotLoaded
    case invalidConfiguration
    case connectionFailed(String)
    case extensionNotApproved  // macOS-specific

    public var errorDescription: String? {
        switch self {
        case .configurationNotLoaded:
            return "VPN configuration not loaded"
        case .invalidConfiguration:
            return "Invalid VPN configuration"
        case .connectionFailed(let reason):
            return "Connection failed: \(reason)"
        case .extensionNotApproved:
            #if os(macOS)
            return "Network Extension not approved. Open System Settings → Privacy & Security and click 'Allow' for TunnelProvider."
            #else
            return "Network Extension not approved"
            #endif
        }
    }
}
