import Foundation

struct ValidationError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw ValidationError(message: message) }
}

func plist(at url: URL) throws -> [String: Any] {
    let data = try Data(contentsOf: url)
    guard let value = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
        throw ValidationError(message: "Invalid property list: \(url.path)")
    }
    return value
}

func codesign(_ arguments: [String], captureErrors: Bool = false) throws -> Data {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    process.arguments = arguments
    let output = Pipe()
    process.standardOutput = output
    if captureErrors { process.standardError = output }
    try process.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    try require(process.terminationStatus == 0, "codesign failed: \(arguments.joined(separator: " "))")
    return data
}

do {
    try require(CommandLine.arguments.count == 2, "Usage: ValidateBundle.swift /path/to/Rayfish.app")
    let app = URL(fileURLWithPath: CommandLine.arguments[1])
    let identifier = "com.rayfish.app.tunnel"
    let extensions = app.appendingPathComponent("Contents/Library/SystemExtensions")
    let names = try FileManager.default.contentsOfDirectory(atPath: extensions.path)
    try require(names == ["\(identifier).systemextension"], "Expected exactly \(identifier).systemextension, found \(names)")
    let bundle = extensions.appendingPathComponent(names[0])
    let info = try plist(at: bundle.appendingPathComponent("Contents/Info.plist"))
    try require(info["CFBundleIdentifier"] as? String == identifier, "Tunnel bundle identifier mismatch")
    try require(info["CFBundlePackageType"] as? String == "SYSX", "Tunnel CFBundlePackageType must be SYSX")
    guard let executable = info["CFBundleExecutable"] as? String else {
        throw ValidationError(message: "Missing tunnel executable name")
    }
    try require(FileManager.default.isExecutableFile(atPath: bundle.appendingPathComponent("Contents/MacOS/\(executable)").path), "Missing tunnel executable")
    let network = info["NetworkExtension"] as? [String: Any] ?? [:]
    let providers = network["NEProviderClasses"] as? [String: String] ?? [:]
    try require(providers["com.apple.networkextension.packet-tunnel"] == "RayfishTunnelExtension.PacketTunnelProvider", "Missing packet tunnel provider class")
    let data = try codesign(["-d", "--entitlements", "-", "--xml", bundle.path])
    let entitlements = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] ?? [:]
    let capabilities = entitlements["com.apple.developer.networking.networkextension"] as? [String] ?? []
    try require(capabilities.contains("packet-tunnel-provider-systemextension"), "Missing signed packet tunnel system-extension entitlement")
    let groups = entitlements["com.apple.security.application-groups"] as? [String] ?? []
    let service = network["NEMachServiceName"] as? String ?? ""
    try require(groups.contains { service.hasPrefix($0 + ".") }, "Mach service must belong to a signed app group")
    for code in [app, bundle, app.appendingPathComponent("Contents/MacOS/ray")] {
        _ = try codesign(["--verify", "--strict", code.path])
        let signature = try codesign(["-dv", "--verbose=2", code.path], captureErrors: true)
        let details = String(decoding: signature, as: UTF8.self)
        try require(details.contains("Authority=Developer ID Application:"), "Missing Developer ID signature: \(code.path)")
        try require(details.contains("(runtime)"), "Hardened runtime is disabled: \(code.path)")
        try require(details.contains("Timestamp="), "Missing secure signing timestamp: \(code.path)")
        let signedData = try codesign(["-d", "--entitlements", "-", "--xml", code.path])
        if !signedData.isEmpty {
            let signedEntitlements = try PropertyListSerialization.propertyList(from: signedData, format: nil) as? [String: Any] ?? [:]
            try require(signedEntitlements["com.apple.security.get-task-allow"] as? Bool != true, "Release includes debugging entitlement: \(code.path)")
        }
    }
    print("Rayfish release packaging and signing checks passed; notarization is checked separately with macos-assess")
} catch {
    FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
    exit(1)
}
