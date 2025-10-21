import Foundation
import NetworkExtension
import Combine
import CryptoKit
import VpnCoreKit

@MainActor
public class VPNManager: ObservableObject {
    @Published public var connectionStatus: VPNConnectionStatus = .disconnected
    @Published public var isConnecting = false
    @Published public var statusMessage = "Disconnected"

    private var currentProvider: VPNProvider?
    private var statusObserver: NSObjectProtocol?

    private let appGroup: String
    private let bundleIdentifier: String

    public var isConnected: Bool {
        connectionStatus == .connected
    }

    public init(appGroup: String, bundleIdentifier: String) {
        self.appGroup = appGroup
        self.bundleIdentifier = bundleIdentifier
        observeVPNStatus()
    }

    // MARK: - Public Methods

    public func connect(with config: VpnCoreKit.ServerConfiguration, protocolType: VPNProtocolType = .openVPN) async {
        isConnecting = true
        statusMessage = "Connecting..."

        VPNLog.info("Connecting: \(config.name) (\(protocolType.displayName))")

        do {
            let provider = createProvider(for: protocolType)
            currentProvider = provider

            try await provider.loadConfiguration()
            try await provider.connect(with: config)

            VPNLog.info("Connection initiated")

        } catch {
            isConnecting = false
            statusMessage = "Connection failed: \(error.localizedDescription)"
            VPNLog.error("Connection failed: \(error.localizedDescription)")
        }
    }

    public func disconnect() async {
        statusMessage = "Disconnecting..."

        do {
            try await currentProvider?.disconnect()
        } catch {
            print("Disconnect error: \(error)")
        }
    }

    // MARK: - Private Methods

    private func createProvider(for type: VPNProtocolType) -> VPNProvider {
        switch type {
        case .openVPN:
            return OpenVPNProvider(appGroup: appGroup, bundleIdentifier: bundleIdentifier)
        case .ikev2:
            return IKEv2Provider()
        case .wireGuard:
            // Future: return WireGuardProvider()
            fatalError("WireGuard not yet implemented")
        }
    }


    private func observeVPNStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let self = self else { return }

            if let connection = notification.object as? NEVPNConnection {
                Task { @MainActor in
                    self.updateStatus(connection.status)
                }
            }
        }

        // Also check current status
        Task {
            let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
            if let status = managers?.first?.connection.status {
                await MainActor.run {
                    self.updateStatus(status)
                }
            }
        }
    }

    private func updateStatus(_ status: NEVPNStatus) {
        let previousStatus = connectionStatus
        connectionStatus = VPNConnectionStatus(from: status)
        statusMessage = connectionStatus.displayText

        // Log status changes
        if previousStatus != connectionStatus {
            VPNLog.info("Status: \(previousStatus.displayText) -> \(connectionStatus.displayText)")
        }

        switch connectionStatus {
        case .connected:
            isConnecting = false
        case .connecting:
            isConnecting = true
        case .reasserting:
            isConnecting = true
        case .disconnected:
            isConnecting = false
        case .invalid:
            isConnecting = false
            VPNLog.error("Invalid configuration")
        case .disconnecting:
            isConnecting = true
        }

        // Update provider status
        currentProvider?.updateStatus(status)
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }
}
