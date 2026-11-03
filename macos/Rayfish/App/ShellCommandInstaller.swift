import Foundation

enum ShellCommandInstaller {
    private static let marker = "# Rayfish command"
    private static let completionMarker = "# Rayfish completion"
    private static let endMarker = "# End Rayfish command"

    static func install(
        executable: URL = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/ray"),
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> URL {
        let configuration = try shellConfiguration(home: home, environment: environment)

        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw ShellCommandError.commandMissing
        }

        let existing = if FileManager.default.fileExists(atPath: configuration.path) {
            try String(contentsOf: configuration, encoding: .utf8)
        } else {
            ""
        }
        let contents = replacingCommand(
            in: existing, executable: executable.path, shell: shellName(environment: environment))
        try FileManager.default.createDirectory(
            at: configuration.deletingLastPathComponent(), withIntermediateDirectories: true)
        try contents.write(to: configuration, atomically: true, encoding: .utf8)
        return configuration
    }

    static func shellName(environment: [String: String] = ProcessInfo.processInfo.environment) -> String {
        let name = URL(fileURLWithPath: environment["SHELL"] ?? "")
            .lastPathComponent
        if name == "zsh" || name == "bash" || name == "fish" {
            return name
        }
        return "shell"
    }

    private static func shellConfiguration(home: URL, environment: [String: String]) throws -> URL {
        let shell = environment["SHELL"] ?? ""
        let fileName: String
        switch URL(fileURLWithPath: shell).lastPathComponent {
        case "zsh":
            fileName = ".zshrc"
        case "bash":
            fileName = ".bashrc"
        case "fish":
            let config = environment["XDG_CONFIG_HOME"]
                .flatMap { $0.hasPrefix("/") ? URL(fileURLWithPath: $0) : nil }
                ?? home.appendingPathComponent(".config")
            return config.appendingPathComponent("fish/config.fish")
        default:
            throw ShellCommandError.unsupportedShell(shell)
        }
        return home.appendingPathComponent(fileName)
    }

    static func replacingCommand(in contents: String, executable: String, shell: String) -> String {
        let lines = contents.components(separatedBy: .newlines)
        var retained: [String] = []
        var index = 0
        while index < lines.count {
            if lines[index] == marker {
                index += 1
                if index < lines.count,
                   lines[index].hasPrefix("alias ray=") || lines[index].hasPrefix("alias ray ") {
                    index += 1
                }
                if index < lines.count, lines[index] == completionMarker {
                    index += 1
                    while index < lines.count, lines[index] != endMarker {
                        index += 1
                    }
                    if index < lines.count {
                        index += 1
                    }
                }
                continue
            }
            retained.append(lines[index])
            index += 1
        }

        // Quote the executable when the alias runs, then quote that alias value.
        let aliasValue = shellQuoted(shellQuoted(executable, shell: shell), shell: shell)
        let command = shell == "fish" ? "alias ray \(aliasValue)" : "alias ray=\(aliasValue)"
        let completion: String
        switch shell {
        case "zsh":
            completion = """
            if (( ! $+functions[compdef] )); then
              autoload -Uz compinit && compinit
            fi
            source <(\(shellQuoted(executable)) completions zsh)
            """
        case "bash":
            completion = "eval \"$(\(shellQuoted(executable)) completions bash)\""
        case "fish":
            completion = "\(shellQuoted(executable, shell: shell)) completions fish | source"
        default:
            completion = ""
        }
        return retained.joined(separator: "\n").trimmingCharacters(in: .newlines)
            + "\n\n\(marker)\n\(command)\n\(completionMarker)\n\(completion)\n\(endMarker)\n"
    }

    private static func shellQuoted(_ value: String, shell: String = "sh") -> String {
        if shell == "fish" {
            let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "'", with: "\\'")
            return "'\(escaped)'"
        }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
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
            "Rayfish can install the command for zsh, bash, or fish, not \(shell.isEmpty ? "this shell" : shell)."
        }
    }
}
