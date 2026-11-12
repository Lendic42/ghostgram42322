import XCTest
@testable import TelegramCore

final class SideloadStorageContainerTests: XCTestCase {
    func testUsesTheAppGroupWhenTheContainerExists() {
        let group = URL(fileURLWithPath: "/group")
        let support = URL(fileURLWithPath: "/support")
        XCTAssertEqual(storageContainerURL(appGroupContainer: group, applicationSupport: support), group)
    }

    func testFallsBackToApplicationSupportWhenTheAppGroupIsMissing() {
        let support = URL(fileURLWithPath: "/support")
        XCTAssertEqual(
            storageContainerURL(appGroupContainer: nil, applicationSupport: support),
            support.appendingPathComponent(sideloadAppGroupDirectoryName)
        )
    }
}
