import Foundation

enum ShellCommandInstaller {
    private static let marker = "# Rayfish command"

    static func install() throws -> URL {
        let configuration = try shellConfiguration()
        let executable = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/ray")

        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw ShellCommandError.commandMissing
        }

        let existing = if FileManager.default.fileExists(atPath: configuration.path) {
            try String(contentsOf: configuration, encoding: .utf8)
        } else {
            ""
        }
        let contents = replacingCommand(in: existing, executable: executable.path)
        try contents.write(to: configuration, atomically: true, encoding: .utf8)
        return configuration
    }

    static func shellName() -> String {
        let name = URL(fileURLWithPath: ProcessInfo.processInfo.environment["SHELL"] ?? "")
            .lastPathComponent
        if name == "zsh" || name == "bash" {
            return name
        }
        return "shell"
    }

    private static func shellConfiguration() throws -> URL {
        let shell = ProcessInfo.processInfo.environment["SHELL"] ?? ""
        let fileName: String
        switch URL(fileURLWithPath: shell).lastPathComponent {
        case "zsh":
            fileName = ".zshrc"
        case "bash":
            fileName = ".bashrc"
        default:
            throw ShellCommandError.unsupportedShell(shell)
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(fileName)
    }

    static func replacingCommand(in contents: String, executable: String) -> String {
        let lines = contents.components(separatedBy: .newlines)
        var retained: [String] = []
        var index = 0
        while index < lines.count {
            if lines[index] == marker {
                index += 1
                if index < lines.count, lines[index].hasPrefix("alias ray=") {
                    index += 1
                }
                continue
            }
            retained.append(lines[index])
            index += 1
        }

        // Quote the executable when the alias runs, then quote that alias value.
        let command = "alias ray=\(shellQuoted(shellQuoted(executable)))"
        return retained.joined(separator: "\n").trimmingCharacters(in: .newlines)
            + "\n\n\(marker)\n\(command)\n"
    }

    private static func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

private enum ShellCommandError: LocalizedError {
    case commandMissing
    case unsupportedShell(String)

    var errorDescription: String? {
        switch self {
        case .commandMissing:
            "The bundled ray command is missing. Rebuild Rayfish and try again."
        case let .unsupportedShell(shell):
            "Rayfish can install the command for zsh or bash, not \(shell.isEmpty ? "this shell" : shell)."
        }
    }
}
