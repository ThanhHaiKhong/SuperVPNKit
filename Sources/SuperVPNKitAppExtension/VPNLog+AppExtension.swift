import Foundation
import OSLog

/// Logging utilities for app extension
/// Simplified version that works in network extensions
public enum VPNLogExtension {
    /// Log debug message
    public static func debug(_ message: String) {
        #if DEBUG
        NSLog("🔍 [DEBUG] \(message)")
        #endif
    }

    /// Log info message
    public static func info(_ message: String) {
        NSLog("ℹ️ [INFO] \(message)")
    }

    /// Log error message
    public static func error(_ message: String) {
        NSLog("❌ [ERROR] \(message)")
    }

    /// Log warning message
    public static func warning(_ message: String) {
        NSLog("⚠️ [WARN] \(message)")
    }
}
