import Foundation
import OSLog

/// Custom logging system for SuperVPN using OSLog
public enum VPNLog {
    private static let subsystem = "app.supervpn.kit"

    // Category loggers
    public static let vpn = Logger(subsystem: subsystem, category: "vpn")
    public static let openvpn = Logger(subsystem: subsystem, category: "openvpn")
    public static let ikev2 = Logger(subsystem: subsystem, category: "ikev2")
    public static let api = Logger(subsystem: subsystem, category: "api")
    public static let ui = Logger(subsystem: subsystem, category: "ui")

    /// Log levels mapped to OSLog levels
    public static func debug(_ message: String, category: Logger = VPNLog.vpn) {
        #if DEBUG
        category.debug("\(message, privacy: .public)")
        #endif
    }

    public static func info(_ message: String, category: Logger = VPNLog.vpn) {
        category.info("\(message, privacy: .public)")
    }

    public static func error(_ message: String, category: Logger = VPNLog.vpn) {
        category.error("\(message, privacy: .public)")
    }

    public static func fault(_ message: String, category: Logger = VPNLog.vpn) {
        category.fault("\(message, privacy: .public)")
    }
}
