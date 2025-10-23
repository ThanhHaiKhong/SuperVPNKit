import Foundation
import NetworkExtension
import VpnCoreKit

public class IKEv2Provider: VPNProvider {
    public let protocolType = "IKEv2"

    private var vpnManager: NEVPNManager?

    public init() {}

    public func loadConfiguration() async throws {
        vpnManager = NEVPNManager.shared()
        try await vpnManager?.loadFromPreferences()
    }

    public func connect(with config: VpnCoreKit.ServerConfiguration) async throws {
        VPNLog.info("Connecting to \(config.name) (\(config.host))", category: VPNLog.ikev2)
        VPNLog.debug("Username: \(config.username), Password: \(config.password.prefix(8))...", category: VPNLog.ikev2)

        guard let vpnManager = vpnManager else {
            throw VPNError.configurationNotLoaded
        }

        // Parse strongSwan template
        let ikev2Config = try parseStrongSwanTemplate(config.template)

        // Create IKEv2 protocol configuration
        let ikev2Protocol = NEVPNProtocolIKEv2()

        // Server configuration from template
        ikev2Protocol.serverAddress = ikev2Config.serverAddress ?? config.host
        ikev2Protocol.remoteIdentifier = ikev2Config.remoteIdentifier ?? config.host

        // Set local identifier from template (for IKE identity)
        // Falls back to username if not specified in template
        ikev2Protocol.localIdentifier = ikev2Config.localIdentifier ?? config.username

        // Authentication based on type from template
        try configureAuthentication(
            ikev2Protocol: ikev2Protocol,
            authType: ikev2Config.authType,
            username: config.username,
            password: config.password
        )

        // IKEv2 settings
        if let dpd = ikev2Config.deadPeerDetection {
            ikev2Protocol.deadPeerDetectionRate = dpd > 30 ? .low : .medium
        } else {
            ikev2Protocol.deadPeerDetectionRate = .medium
        }
        ikev2Protocol.disconnectOnSleep = false

        // Import CA certificate if provided - establish trust chain
        if let caCertPEM = ikev2Config.caCertificate,
           let certData = parsePEMCertificate(caCertPEM),
           let certificate = SecCertificateCreateWithData(nil, certData as CFData) {

            // Import CA into system trust
            try importCATrustChain(certificate)

            // Extract and set issuer CN for validation
            if let issuerCN = extractCommonName(from: certificate) {
                ikev2Protocol.serverCertificateIssuerCommonName = issuerCN
                VPNLog.debug("CA cert issuer CN: \(issuerCN)", category: VPNLog.ikev2)
            }

            VPNLog.debug("CA trust chain established", category: VPNLog.ikev2)
        }

        VPNLog.debug("Server: \(ikev2Protocol.serverAddress ?? "nil"), RemoteId: \(ikev2Protocol.remoteIdentifier ?? "nil"), LocalId: \(ikev2Protocol.localIdentifier ?? "nil")", category: VPNLog.ikev2)

        // Log proposals (iOS uses built-in negotiation, these are for documentation)
        if !ikev2Config.ikeProposals.isEmpty {
            VPNLog.debug("IKE proposals: \(ikev2Config.ikeProposals.joined(separator: ", "))", category: VPNLog.ikev2)
        }
        if !ikev2Config.espProposals.isEmpty {
            VPNLog.debug("ESP proposals: \(ikev2Config.espProposals.joined(separator: ", "))", category: VPNLog.ikev2)
        }

        // Configure VPN manager
        vpnManager.protocolConfiguration = ikev2Protocol
        vpnManager.localizedDescription = "SuperVPN - IKEv2"
        vpnManager.isEnabled = true
        vpnManager.isOnDemandEnabled = false

        try await vpnManager.saveToPreferences()
        try await vpnManager.loadFromPreferences()

        VPNLog.info("Starting tunnel", category: VPNLog.ikev2)

        do {
            try vpnManager.connection.startVPNTunnel()
        } catch let error as NSError {
            #if os(macOS)
            // macOS-specific error handling
            if error.code == 4 || error.code == 1 {
                VPNLog.error("VPN permission denied (error \(error.code))", category: VPNLog.ikev2)
                throw VPNError.connectionFailed("VPN permission denied. Click 'Allow' when prompted.")
            }
            #endif
            VPNLog.error("Failed to start tunnel: \(error.localizedDescription)", category: VPNLog.ikev2)
            throw VPNError.connectionFailed(error.localizedDescription)
        }
    }

    public func disconnect() async throws {
        vpnManager?.connection.stopVPNTunnel()
    }

    public func updateStatus(_ status: NEVPNStatus) {
        // Status updates are handled by the VPNManager
    }

    public func getConnection() -> NEVPNConnection? {
        return vpnManager?.connection
    }

    public func getDataCount() -> (received: UInt64, sent: UInt64)? {
        // IKEv2 doesn't expose data count through NetworkExtension API
        // Would require custom implementation or system-level monitoring
        return nil
    }

    // MARK: - Private Methods

    private func parseStrongSwanTemplate(_ template: String?) throws -> IKEv2Configuration {
        guard let template = template else {
            throw VPNError.invalidConfiguration
        }

        guard let jsonData = template.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw VPNError.invalidConfiguration
        }

        return try parseStrongSwanJSON(json)
    }

    private func parseStrongSwanJSON(_ json: [String: Any]) throws -> IKEv2Configuration {
        var config = IKEv2Configuration()

        // Parse remote server configuration
        if let remote = json["remote"] as? [String: Any] {
            config.serverAddress = remote["addr"] as? String
            config.serverPort = remote["port"] as? Int ?? 4500
            config.remoteIdentifier = remote["id"] as? String
            config.caCertificate = remote["cert"] as? String
        }

        // Parse local configuration
        if let local = json["local"] as? [String: Any] {
            config.localIdentifier = local["id"] as? String
        }

        // Parse type (ikev2-eap, ikev2-cert, etc.)
        config.authType = json["type"] as? String

        // Parse IKE proposals (supports both string and array)
        if let ikeProposal = json["ike-proposal"] as? String {
            config.ikeProposals = [ikeProposal]
        } else if let ikeProposals = json["ike-proposal"] as? [String] {
            config.ikeProposals = ikeProposals
        }

        // Parse ESP proposals (supports both string and array)
        if let espProposal = json["esp-proposal"] as? String {
            config.espProposals = [espProposal]
        } else if let espProposals = json["esp-proposal"] as? [String] {
            config.espProposals = espProposals
        }

        // Parse DPD settings
        if let ikeDpd = json["ike-dpd"] as? Int {
            config.deadPeerDetection = ikeDpd
        }

        // Parse flags
        if let flags = json["flags"] as? [String: Any] {
            config.ipv6Enabled = flags["ipv6"] as? Bool ?? false
        }

        return config
    }

    private func parsePEMCertificate(_ pem: String) -> Data? {
        // Remove PEM headers and whitespace
        let cleanedPEM = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespaces)

        return Data(base64Encoded: cleanedPEM)
    }

    private func configureAuthentication(
        ikev2Protocol: NEVPNProtocolIKEv2,
        authType: String?,
        username: String,
        password: String
    ) throws {
        // Determine auth method from template type
        let authMethod = authType?.lowercased() ?? "ikev2-eap"

        switch authMethod {
        case "ikev2-eap":
            // EAP-MSCHAPv2 authentication (username/password)
            // iOS automatically negotiates MSCHAPv2 when useExtendedAuthentication = true
            ikev2Protocol.authenticationMethod = .none
            ikev2Protocol.useExtendedAuthentication = true
            ikev2Protocol.username = username
            ikev2Protocol.passwordReference = try storePasswordInKeychain(
                password: password,
                username: username
            )
            VPNLog.debug("Auth: EAP-MSCHAPv2 (username/password)", category: VPNLog.ikev2)
            VPNLog.debug("EAP Identity: \(username)", category: VPNLog.ikev2)

        case "ikev2-cert":
            // Certificate-based authentication
            ikev2Protocol.authenticationMethod = .certificate
            // Certificate identity would be set via identityData
            VPNLog.debug("Auth: Certificate", category: VPNLog.ikev2)

        case "ikev2-psk":
            // Pre-shared key authentication
            ikev2Protocol.authenticationMethod = .sharedSecret
            ikev2Protocol.sharedSecretReference = try storePasswordInKeychain(
                password: password,
                username: "psk-\(username)"
            )
            VPNLog.debug("Auth: PSK", category: VPNLog.ikev2)

        default:
            // Default to EAP
            ikev2Protocol.authenticationMethod = .none
            ikev2Protocol.useExtendedAuthentication = true
            ikev2Protocol.username = username
            ikev2Protocol.passwordReference = try storePasswordInKeychain(
                password: password,
                username: username
            )
            VPNLog.debug("Auth: EAP (default)", category: VPNLog.ikev2)
        }
    }

    private func extractCommonName(from certificate: SecCertificate) -> String? {
        var commonName: CFString?
        let status = SecCertificateCopyCommonName(certificate, &commonName)

        if status == errSecSuccess, let cn = commonName as String? {
            return cn
        }

        return nil
    }

    private func importCATrustChain(_ certificate: SecCertificate) throws {
        // Add CA certificate to keychain for trust validation
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: "SuperVPN-IKEv2-CA"
        ]

        // Delete existing if present
        SecItemDelete(addQuery as CFDictionary)

        // Add certificate to keychain
        let status = SecItemAdd(addQuery as CFDictionary, nil)

        if status != errSecSuccess && status != errSecDuplicateItem {
            VPNLog.error("Failed to import CA cert: \(status)", category: VPNLog.ikev2)
            throw VPNError.connectionFailed("Failed to import CA certificate")
        }

        VPNLog.debug("CA certificate imported to keychain", category: VPNLog.ikev2)
    }

    private func storePasswordInKeychain(password: String, username: String) throws -> Data {
        // Account = username + protocol to avoid conflicts
        let keychainAccount = "\(username)-IKEV2"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrService as String: "SuperVPN-IKEv2",
            kSecValueData as String: password.data(using: .utf8)!,
            kSecReturnPersistentRef as String: true
        ]

        // Delete existing item
        SecItemDelete(query as CFDictionary)

        // Add new item
        var ref: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &ref)

        guard status == errSecSuccess, let persistentRef = ref as? Data else {
            throw VPNError.connectionFailed("Failed to store password in keychain")
        }

        return persistentRef
    }
}

// MARK: - IKEv2 Configuration

private struct IKEv2Configuration {
    var serverAddress: String?
    var serverPort: Int = 4500
    var remoteIdentifier: String?
    var localIdentifier: String?
    var caCertificate: String?
    var authType: String?
    var deadPeerDetection: Int?
    var ipv6Enabled: Bool = false

    // Note: iOS NEVPNProtocolIKEv2 doesn't support custom proposals
    // These are parsed for documentation/compatibility but not used
    var ikeProposals: [String] = []
    var espProposals: [String] = []
}
