import NetworkExtension
import TunnelKitOpenVPNAppExtension
import TunnelKitCore

/// Base class for SuperVPN tunnel provider
/// Provides common configuration and logging for OpenVPN tunnels
open class SuperVPNTunnelProvider: OpenVPNTunnelProvider {

    /// Initializes the tunnel provider
    public override init() {
        super.init()
        configureDefaults()
    }

    /// Configure default settings for the tunnel
    open func configureDefaults() {
        // Set data count interval (how often to update byte counts)
        dataCountInterval = 3000 // Update every 3 seconds

        #if DEBUG
        // Enable debug logging in debug builds
        debugLogLevel = .debug
        CoreConfiguration.masksPrivateData = false
        VPNLogExtension.debug("SuperVPNTunnelProvider initialized with debug logging")
        #else
        // Use info level in release builds
        debugLogLevel = .info
        CoreConfiguration.masksPrivateData = true
        #endif
    }

    /// Called when the tunnel is starting
    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        NSLog("🚀 [SuperVPNTunnelProvider] Starting tunnel at \(Date())")
        VPNLogExtension.info("Starting VPN tunnel")

        // Log options if provided
        if let options = options {
            NSLog("📋 [SuperVPNTunnelProvider] Tunnel options: \(options)")
            VPNLogExtension.debug("Tunnel options: \(options)")
        }

        // Call parent implementation
        super.startTunnel(options: options, completionHandler: completionHandler)
    }

    /// Called when the tunnel stops
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("🛑 [SuperVPNTunnelProvider] Stopping tunnel. Reason: \(reason.rawValue)")
        VPNLogExtension.info("Stopping VPN tunnel. Reason: \(reason.rawValue)")

        // Call parent implementation
        super.stopTunnel(with: reason, completionHandler: completionHandler)
    }

    /// Called when the tunnel encounters an error
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        NSLog("📨 [SuperVPNTunnelProvider] Received app message")
        VPNLogExtension.debug("Received app message")

        // Call parent implementation
        super.handleAppMessage(messageData, completionHandler: completionHandler)
    }

    /// Called when tunnel configuration changes
    open override func sleep(completionHandler: @escaping () -> Void) {
        NSLog("😴 [SuperVPNTunnelProvider] Entering sleep mode")
        VPNLogExtension.debug("Entering sleep mode")

        // Call parent implementation
        super.sleep(completionHandler: completionHandler)
    }

    /// Called when tunnel wakes from sleep
    open override func wake() {
        NSLog("⏰ [SuperVPNTunnelProvider] Waking from sleep")
        VPNLogExtension.debug("Waking from sleep")

        // Call parent implementation
        super.wake()
    }
}
