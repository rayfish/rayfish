import XCTest

/// Drives the simulator build end to end: first run, create a network, invite,
/// and each tab. The node runs in the app process there, so this covers the
/// core without a packet tunnel. Screenshots go to SCREENSHOT_DIR when set.
final class WalkthroughTests: XCTestCase {
    private var app: XCUIApplication!

    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launch()
    }

    func testWalkthrough() {
        let getStarted = app.buttons["Get started"]
        if getStarted.waitForExistence(timeout: 5) {
            shot("welcome")
            getStarted.tap()
        }
        XCTAssertTrue(app.tabBars.buttons["Home"].waitForExistence(timeout: 15))
        allowNotifications()
        XCTAssertTrue(app.staticTexts["Tunnel"].waitForExistence(timeout: 30))
        shot("home")

        app.tabBars.buttons["Networks"].tap()
        let add = app.buttons["Join or create a network"]
        if add.waitForExistence(timeout: 10) {
            shot("networks-empty")
            add.tap()
            XCTAssertTrue(app.buttons["Create network"].waitForExistence(timeout: 5))
            shot("add-network")
            app.buttons["Create network"].tap()
        }
        let row = app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'online' OR label CONTAINS 'offline'")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 30))
        shot("networks")
        row.tap()
        XCTAssertTrue(app.staticTexts["Hostname"].waitForExistence(timeout: 10))
        sleep(2)
        shot("network-detail")
        app.buttons["More"].firstMatch.tap()
        app.buttons["Invite"].tap()
        XCTAssertTrue(app.buttons["Copy code"].waitForExistence(timeout: 30))
        shot("invite")
        app.swipeDown(velocity: .fast)

        app.tabBars.buttons["Home"].tap()
        sleep(1)
        shot("home-connected")
        app.tabBars.buttons["You"].tap()
        XCTAssertTrue(app.staticTexts["THIS DEVICE"].waitForExistence(timeout: 5) || app.staticTexts["This device"].exists)
        shot("you")
        app.swipeUp()
        shot("you-bottom")
        XCTAssertTrue(app.buttons["iphone ✎"].exists)

        app.buttons["Back up"].tap()
        let password = app.secureTextFields.element(boundBy: 0)
        XCTAssertTrue(password.waitForExistence(timeout: 5))
        password.tap()
        password.typeText("correct horse")
        let confirm = app.secureTextFields.element(boundBy: 1)
        confirm.tap()
        confirm.typeText("correct horse")
        app.buttons["Save backup"].tap()
        // The system file exporter appears once the identity is sealed.
        sleep(5)
        shot("backup-export")
    }

    private func allowNotifications() {
        let alert = XCUIApplication(bundleIdentifier: "com.apple.springboard").alerts.firstMatch
        if alert.waitForExistence(timeout: 3) {
            alert.buttons["Allow"].tap()
        }
    }

    private func shot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
        if let dir = ProcessInfo.processInfo.environment["SCREENSHOT_DIR"] {
            try? XCUIScreen.main.screenshot().pngRepresentation
                .write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
        }
    }
}
