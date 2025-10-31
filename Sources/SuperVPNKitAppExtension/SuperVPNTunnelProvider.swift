import NetworkExtension
import TunnelKitOpenVPNAppExtension
import TunnelKitCore
import Darwin

/// Base class for SuperVPN tunnel provider
/// Provides common configuration and logging for OpenVPN tunnels
open class SuperVPNTunnelProvider: OpenVPNTunnelProvider {

    private var statsUpdateTimer: DispatchSourceTimer?
    private var appGroupIdentifier: String?
    private var initialBytesReceived: UInt64 = 0
    private var initialBytesSent: UInt64 = 0

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

        // Extract app group identifier from protocol configuration
        if let protocolConfig = self.protocolConfiguration as? NETunnelProviderProtocol,
           let providerConfig = protocolConfig.providerConfiguration,
           let appGroup = providerConfig["appGroup"] as? String {
            self.appGroupIdentifier = appGroup
            NSLog("📱 [SuperVPNTunnelProvider] Using app group: \(appGroup)")
        }

        // Reset initial stats - they will be captured on first stats update
        initialBytesReceived = 0
        initialBytesSent = 0
        NSLog("📊 [SuperVPNTunnelProvider] Initial stats reset to 0 - will capture baseline on first update")

        // Start stats update timer
        startStatsUpdateTimer()

        // Call parent implementation
        super.startTunnel(options: options, completionHandler: completionHandler)
    }

    /// Called when the tunnel stops
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("🛑 [SuperVPNTunnelProvider] Stopping tunnel. Reason: \(reason.rawValue)")
        VPNLogExtension.info("Stopping VPN tunnel. Reason: \(reason.rawValue)")

        // Stop stats update timer
        stopStatsUpdateTimer()

        // Clear stats from shared UserDefaults
        clearSharedStats()

        // Reset initial byte counts
        initialBytesReceived = 0
        initialBytesSent = 0

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

    // MARK: - Stats Management

    /// Start the timer that periodically writes stats to shared UserDefaults
    private func startStatsUpdateTimer() {
        // Cancel any existing timer
        stopStatsUpdateTimer()

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: .seconds(3))
        timer.setEventHandler { [weak self] in
            self?.updateSharedStats()
        }
        timer.resume()
        statsUpdateTimer = timer

        NSLog("⏱️ [SuperVPNTunnelProvider] Stats update timer started")
    }

    /// Stop the stats update timer
    private func stopStatsUpdateTimer() {
        statsUpdateTimer?.cancel()
        statsUpdateTimer = nil
        NSLog("⏱️ [SuperVPNTunnelProvider] Stats update timer stopped")
    }

    /// Update connection stats in shared UserDefaults
    private func updateSharedStats() {
        guard let appGroup = appGroupIdentifier,
              let sharedDefaults = UserDefaults(suiteName: appGroup) else {
            return
        }

        // Get data count from TunnelKit's built-in data counting
        // TunnelKit automatically writes dataCount to UserDefaults with key "OpenVPN.DataCount"
        // as an array of [received, sent] UInt values
        guard let dataCountArray = sharedDefaults.array(forKey: "OpenVPN.DataCount") as? [UInt],
              dataCountArray.count == 2 else {
            #if DEBUG
            NSLog("⚠️ [SuperVPNTunnelProvider] TunnelKit dataCount not available yet (tunnel may not be fully established)")
            #endif
            return
        }

        let currentReceived = UInt64(dataCountArray[0])
        let currentSent = UInt64(dataCountArray[1])

        // If this is the first update (initial stats are 0), capture the baseline
        if initialBytesReceived == 0 && initialBytesSent == 0 {
            initialBytesReceived = currentReceived
            initialBytesSent = currentSent
            NSLog("📊 [SuperVPNTunnelProvider] Baseline captured: sent=\(initialBytesSent), received=\(initialBytesReceived)")

            // Write zeros for the first update (since we just set the baseline)
            sharedDefaults.set(UInt64(0), forKey: "vpn_bytes_received")
            sharedDefaults.set(UInt64(0), forKey: "vpn_bytes_sent")
            sharedDefaults.set(Date().timeIntervalSince1970, forKey: "vpn_stats_updated_at")
            sharedDefaults.synchronize()
            return
        }

        // Calculate session delta (current - initial)
        let sessionBytesReceived = currentReceived >= initialBytesReceived ? currentReceived - initialBytesReceived : currentReceived
        let sessionBytesSent = currentSent >= initialBytesSent ? currentSent - initialBytesSent : currentSent

        sharedDefaults.set(sessionBytesReceived, forKey: "vpn_bytes_received")
        sharedDefaults.set(sessionBytesSent, forKey: "vpn_bytes_sent")
        sharedDefaults.set(Date().timeIntervalSince1970, forKey: "vpn_stats_updated_at")
        sharedDefaults.synchronize()

        #if DEBUG
        NSLog("📊 [SuperVPNTunnelProvider] Stats updated: sent=\(sessionBytesSent), received=\(sessionBytesReceived) (total: sent=\(currentSent), received=\(currentReceived), initial: sent=\(initialBytesSent), received=\(initialBytesReceived))")
        #endif
    }

    /// Clear stats from shared UserDefaults
    private func clearSharedStats() {
        guard let appGroup = appGroupIdentifier,
              let sharedDefaults = UserDefaults(suiteName: appGroup) else {
            return
        }

        sharedDefaults.removeObject(forKey: "vpn_bytes_received")
        sharedDefaults.removeObject(forKey: "vpn_bytes_sent")
        sharedDefaults.removeObject(forKey: "vpn_stats_updated_at")
        sharedDefaults.synchronize()

        NSLog("🗑️ [SuperVPNTunnelProvider] Stats cleared from shared defaults")
    }
}
