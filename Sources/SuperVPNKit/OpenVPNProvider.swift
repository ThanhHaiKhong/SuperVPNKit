import Foundation
import NetworkExtension
import TunnelKitOpenVPN
import TunnelKitOpenVPNCore
import TunnelKitOpenVPNManager
import TunnelKitManager
import CryptoKit
import VpnCoreKit

public class OpenVPNProvider: VPNProvider {
    public let protocolType = "OpenVPN"

    private var vpnManager: NETunnelProviderManager?
    private let appGroup: String
    private let bundleIdentifier: String

    public init(appGroup: String, bundleIdentifier: String) {
        self.appGroup = appGroup
        self.bundleIdentifier = bundleIdentifier
    }

    public func loadConfiguration() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        vpnManager = managers.first ?? NETunnelProviderManager()
    }

    public func connect(with config: VpnCoreKit.ServerConfiguration) async throws {
        VPNLog.info("Connecting to \(config.name) (\(config.host))", category: VPNLog.openvpn)

        // Load existing VPN managers
        let allManagers = try await NETunnelProviderManager.loadAllFromPreferences()

        // Find existing OpenVPN manager or create new one
        if let existingManager = allManagers.first(where: { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
            return proto.providerBundleIdentifier == bundleIdentifier
        }) {
            VPNLog.debug("Reusing existing profile", category: VPNLog.openvpn)
            self.vpnManager = existingManager
        } else {
            VPNLog.debug("Creating new profile", category: VPNLog.openvpn)
            self.vpnManager = NETunnelProviderManager()
        }

        guard let vpnManager = vpnManager else {
            throw VPNError.configurationNotLoaded
        }

        // Build OpenVPN configuration from template
        let configuration = try buildOpenVPNConfiguration(from: config)

        // Create provider configuration
        let providerConfiguration = OpenVPN.ProviderConfiguration(
            "SuperVPN",
            appGroup: appGroup,
            configuration: configuration
        )

        var modifiedProviderConfig = providerConfiguration
        #if DEBUG
        modifiedProviderConfig.shouldDebug = true
        #endif
        modifiedProviderConfig.masksPrivateData = false
        modifiedProviderConfig.username = config.username

        // Store password in keychain (account = username + protocol)
        let keychain = Keychain(group: appGroup)
        let keychainAccount = "\(config.username)-OPENVPN"
        let passwordReference = try keychain.set(
            password: config.password,
            for: keychainAccount,
            context: bundleIdentifier
        )

        var extra = NetworkExtensionExtra()
        extra.passwordReference = passwordReference

        let protocolConfiguration = try modifiedProviderConfig.asTunnelProtocol(
            withBundleIdentifier: bundleIdentifier,
            extra: extra
        )

        vpnManager.protocolConfiguration = protocolConfiguration
        vpnManager.localizedDescription = "SuperVPN - OpenVPN"
        vpnManager.isEnabled = true

        try await vpnManager.saveToPreferences()
        try await vpnManager.loadFromPreferences()

        VPNLog.info("Starting tunnel", category: VPNLog.openvpn)

        do {
            try vpnManager.connection.startVPNTunnel()
        } catch let error as NSError {
            #if os(macOS)
            // macOS-specific error handling
            if error.code == 4 || error.code == 1 {
                VPNLog.error("Network Extension not approved (error \(error.code))", category: VPNLog.openvpn)
                throw VPNError.extensionNotApproved
            }
            #endif
            VPNLog.error("Failed to start tunnel: \(error.localizedDescription)", category: VPNLog.openvpn)
            throw VPNError.connectionFailed(error.localizedDescription)
        }
    }

    public func disconnect() async throws {
        vpnManager?.connection.stopVPNTunnel()
    }

    public func updateStatus(_ status: NEVPNStatus) {
        // Status updates are handled by the VPNManager
    }

    // MARK: - Private Methods

    private func buildOpenVPNConfiguration(
        from config: VpnCoreKit.ServerConfiguration
    ) throws -> OpenVPN.Configuration {
        guard let templateContent = config.template else {
            throw VPNError.invalidConfiguration
        }

        let result = try OpenVPN.ConfigurationParser.parsed(fromContents: templateContent)
        var builder = result.configuration.builder()
        builder.authUserPass = true

        let builtConfig = builder.build()
        VPNLog.debug("Config: cipher=\(builtConfig.cipher?.rawValue ?? "none"), xor=\(builtConfig.xorMethod != nil)", category: VPNLog.openvpn)
        return builtConfig
    }
}

// MARK: - Data Extension

extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            let bytes = hexString[i..<j]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
            i = j
        }
        self = data
    }
}
