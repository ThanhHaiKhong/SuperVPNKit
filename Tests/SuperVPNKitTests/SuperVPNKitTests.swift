import XCTest
@testable import SuperVPNKit

final class SuperVPNKitTests: XCTestCase {
    func testVPNProtocolTypes() {
        XCTAssertEqual(VPNProtocolType.openVPN.displayName, "OpenVPN")
        XCTAssertEqual(VPNProtocolType.ikev2.displayName, "IKEv2")
        XCTAssertEqual(VPNProtocolType.wireGuard.displayName, "WireGuard")

        XCTAssertTrue(VPNProtocolType.openVPN.isSupported)
        XCTAssertTrue(VPNProtocolType.ikev2.isSupported)
        XCTAssertFalse(VPNProtocolType.wireGuard.isSupported)
    }

    func testVPNConnectionStatus() {
        let connected = VPNConnectionStatus.connected
        XCTAssertTrue(connected.isActive)
        XCTAssertEqual(connected.displayText, "Connected")

        let disconnected = VPNConnectionStatus.disconnected
        XCTAssertFalse(disconnected.isActive)
        XCTAssertEqual(disconnected.displayText, "Disconnected")
    }

    func testStatusColors() {
        let connectedColor = VPNConnectionStatus.connected.statusColor
        XCTAssertEqual(connectedColor.green, 1.0)

        let disconnectedColor = VPNConnectionStatus.disconnected.statusColor
        XCTAssertEqual(disconnectedColor.red, 0.5)
    }
}
