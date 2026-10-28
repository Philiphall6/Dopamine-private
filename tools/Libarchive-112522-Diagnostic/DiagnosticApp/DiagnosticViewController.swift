import Foundation
import UIKit
import UniformTypeIdentifiers
import CryptoKit

private enum DiagnosticState: String {
    case testNotStarted = "TEST_NOT_STARTED"
    case controlArchivePass = "CONTROL_ARCHIVE_PASS"
    case testArchivePass = "TEST_ARCHIVE_PASS"
    case longPathControlPass = "LONG_PATH_CONTROL_PASS"
    case testArchiveRejected = "TEST_ARCHIVE_REJECTED"
    case testArchiveError = "TEST_ARCHIVE_ERROR"
    case testInterrupted = "TEST_INTERRUPTED"
}

private final class DiagnosticLogger {
    private let fileManager = FileManager.default
    private let documentsURL: URL
    private let logURL: URL
    private let stateURL: URL

    init() {
        documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        logURL = documentsURL.appendingPathComponent("CVE-2026-112522.jsonl")
        stateURL = documentsURL.appendingPathComponent("CVE-2026-112522.state")
        if !fileManager.fileExists(atPath: logURL.path) {
            fileManager.createFile(atPath: logURL.path, contents: nil)
        }
    }

    var logFileURL: URL { logURL }
    var stateFileURL: URL { stateURL }

    var lastState: String? {
        try? String(contentsOf: stateURL, encoding: .utf8)
    }

    func setState(_ state: DiagnosticState, details: [String: Any] = [:]) {
        try? state.rawValue.write(to: stateURL, atomically: true, encoding: .utf8)
        event("state", state: state.rawValue, details: details)
    }

    func event(_ name: String, state: String? = nil, details: [String: Any] = [:]) {
        var record: [String: Any] = [
            "event": name,
            "wall_time": ISO8601DateFormatter().string(from: Date()),
            "monotonic_seconds": ProcessInfo.processInfo.systemUptime,
            "device_model": Self.machineIdentifier(),
            "ios_version": UIDevice.current.systemVersion,
            "app_bundle": Bundle.main.bundleIdentifier ?? "unknown"
        ]
        if let state {
            record["state"] = state
        }
        details.forEach { record[$0.key] = $0.value }

        guard JSONSerialization.isValidJSONObject(record),
              let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]),
              let line = String(data: data, encoding: .utf8)?.appending("\n"),
              let handle = try? FileHandle(forWritingTo: logURL) else {
            return
        }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(line.utf8))
        try? handle.synchronize()
    }

    private static func machineIdentifier() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        return withUnsafeBytes(of: &systemInfo.machine) { rawBuffer in
            String(decoding: rawBuffer.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }
}

private final class ArchiveRenderer {
    let logger: DiagnosticLogger

    init(logger: DiagnosticLogger) {
        self.logger = logger
    }

    func process(url: URL, label: String, stateOnPass: DiagnosticState) -> DiagnosticState {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let data = try? Data(contentsOf: url)
        logger.event("archive_input_ready", details: [
            "label": label,
            "name": url.lastPathComponent,
            "size": attributes?[.size] ?? 0,
            "sha256": data.map(Self.sha256) ?? "unavailable",
            "path_extension": url.pathExtension.lowercased(),
            "parser": "libarchive",
            "format": "ISO9660/Joliet"
        ])

        var kind = [CChar](repeating: 0, count: 64)
        var message = [CChar](repeating: 0, count: 512)
        var formatName = [CChar](repeating: 0, count: 128)
        var pathList = [CChar](repeating: 0, count: 8192)
        var pathCount: UInt64 = 0
        var maxPathUTF16BEBytes: UInt64 = 0
        var entries: UInt64 = 0
        var bytes: UInt64 = 0

        logger.event("libarchive_start", details: [
            "label": label,
            "api": "dlopen + archive_read_open_filename + archive_read_next_header"
        ])
        let result = url.path.withCString { path in
            kind.withUnsafeMutableBufferPointer { kindBuffer in
                message.withUnsafeMutableBufferPointer { messageBuffer in
                    formatName.withUnsafeMutableBufferPointer { formatBuffer in
                        pathList.withUnsafeMutableBufferPointer { pathBuffer in
                            LAProcessISO(
                                path,
                                kindBuffer.baseAddress,
                                kindBuffer.count,
                                messageBuffer.baseAddress,
                                messageBuffer.count,
                                formatBuffer.baseAddress,
                                formatBuffer.count,
                                pathBuffer.baseAddress,
                                pathBuffer.count,
                                &pathCount,
                                &maxPathUTF16BEBytes,
                                &entries,
                                &bytes
                            )
                        }
                    }
                }
            }
        }
        let resultKind = kind.withUnsafeBufferPointer { buffer in
            String(cString: buffer.baseAddress!)
        }
        let resultMessage = message.withUnsafeBufferPointer { buffer in
            String(cString: buffer.baseAddress!)
        }
        let resultFormat = formatName.withUnsafeBufferPointer { buffer in
            String(cString: buffer.baseAddress!)
        }
        let observedPaths = pathList.withUnsafeBufferPointer { buffer -> [[String: Any]] in
            let value = String(cString: buffer.baseAddress!)
            guard !value.isEmpty else { return [] }
            return value.split(separator: "\n", omittingEmptySubsequences: true).map { rawPath in
                let path = String(rawPath)
                return [
                    "path": String(path.prefix(256)),
                    "truncated": path.count > 256,
                    "utf16be_bytes": path.utf16.count * 2
                ]
            }
        }
        let pathCaptureTruncated = pathCount > UInt64(observedPaths.count) || observedPaths.contains {
            ($0["truncated"] as? Bool) == true
        }
        logger.event("libarchive_complete", details: [
            "label": label,
            "return_code": result,
            "kind": resultKind,
            "message": resultMessage,
            "format": resultFormat.isEmpty ? "unknown" : resultFormat,
            "entries": entries,
            "bytes": bytes,
            "path_count": pathCount,
            "max_path_utf16be_bytes": maxPathUTF16BEBytes,
            "paths": observedPaths,
            "path_capture_capacity": 8192,
            "path_capture_truncated": pathCaptureTruncated
        ])

        if !resultFormat.isEmpty {
            logger.event("archive_format_recognized", details: [
                "classification": "ARCHIVE_FORMAT_RECOGNIZED",
                "format": resultFormat
            ])
        }
        if result == 0 && pathCount > 0 {
            logger.event("joliet_entries_observed", details: [
                "classification": resultKind == "LONG_PATH_CONTROL_PASS"
                    ? "LONG_PATH_CONTROL_PASS"
                    : "JOLIET_ENTRIES_OBSERVED",
                "path_count": pathCount,
                "max_path_utf16be_bytes": maxPathUTF16BEBytes
            ])
        }
        logger.event("runtime_function_invocation_not_proven", details: [
            "classification": "RUNTIME_FUNCTION_INVOCATION_NOT_PROVEN",
            "function": "_build_pathname_utf16be",
            "reason": "public libarchive API observations do not identify an internal instruction"
        ])

        if result == 0 {
            let finalState = resultKind == "LONG_PATH_CONTROL_PASS" ? .longPathControlPass : stateOnPass
            logger.setState(finalState, details: [
                "label": label,
                "entries": entries,
                "max_path_utf16be_bytes": maxPathUTF16BEBytes,
                "classification": resultKind
            ])
            return finalState
        }
        if result == 1 {
            logger.setState(.testArchiveRejected, details: ["label": label, "kind": resultKind])
            return .testArchiveRejected
        }
        logger.setState(.testArchiveError, details: ["label": label, "kind": resultKind])
        return .testArchiveError
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

final class DiagnosticViewController: UIViewController, UIDocumentPickerDelegate {
    private let logger = DiagnosticLogger()
    private lazy var renderer = ArchiveRenderer(logger: logger)
    private let statusLabel = UILabel()
    private let controlButton = UIButton(type: .system)
    private let manualButton = UIButton(type: .system)
    private let exportButton = UIButton(type: .system)

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = "libarchive diagnostic"

        let previousState = logger.lastState ?? DiagnosticState.testNotStarted.rawValue
        logger.event("application_launch", details: ["previous_state": previousState])
        statusLabel.numberOfLines = 0
        statusLabel.textAlignment = .center
        statusLabel.text = previousState == DiagnosticState.testInterrupted.rawValue
            ? "TEST_INTERRUPTED\nRécupérer le journal et un éventuel .ips avant de relancer si l'application s'est fermée."
            : "Contrôle ISO normal avant le test manuel.\nAucun fichier manuel n'est lancé automatiquement."

        configure(controlButton, title: "Contrôle ISO normal", action: #selector(runControl))
        configure(manualButton, title: "Choisir un ISO (manuel)", action: #selector(chooseManualFile))
        configure(exportButton, title: "Exporter les journaux", action: #selector(exportLogs))

        let stack = UIStackView(arrangedSubviews: [statusLabel, controlButton, manualButton, exportButton])
        stack.axis = .vertical
        stack.spacing = 16
        stack.alignment = .fill
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24),
            stack.centerYAnchor.constraint(equalTo: view.safeAreaLayoutGuide.centerYAnchor)
        ])
    }

    @objc private func runControl() {
        guard let url = Bundle.main.url(forResource: "control", withExtension: "iso") else {
            logger.setState(.testArchiveError, details: ["reason": "embedded control ISO missing"])
            statusLabel.text = "TEST_ARCHIVE_ERROR\nISO de contrôle absente"
            return
        }
        logger.event("control_start")
        let state = renderer.process(url: url, label: "embedded-control", stateOnPass: .controlArchivePass)
        statusLabel.text = state == .controlArchivePass
            ? "CONTROL_ARCHIVE_PASS\nISO9660/Joliet valide traitée par libarchive"
            : "TEST_ARCHIVE_ERROR\nLe contrôle n'est pas concluant"
    }

    @objc private func chooseManualFile() {
        logger.event("manual_picker_open")
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        picker.delegate = self
        picker.allowsMultipleSelection = false
        present(picker, animated: true)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let sourceURL = urls.first else { return }
        let alert = UIAlertController(
            title: "Test manuel",
            message: "Le fichier choisi sera remis à libarchive après confirmation. L'application ne génère aucun fichier malformé et ne relance pas automatiquement le test après une fermeture.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Annuler", style: .cancel))
        alert.addAction(UIAlertAction(title: "Lancer", style: .destructive) { [weak self] _ in
            self?.runManualFile(sourceURL)
        })
        present(alert, animated: true)
    }

    private func runManualFile(_ sourceURL: URL) {
        controlButton.isEnabled = false
        manualButton.isEnabled = false
        statusLabel.text = "TEST_INTERRUPTED\nMarqueur écrit avant libarchive…"

        let destination = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("manual-input.iso")
        do {
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.copyItem(at: sourceURL, to: destination)
            let inputData = try Data(contentsOf: destination)
            let inputSHA = SHA256.hash(data: inputData).map { String(format: "%02x", $0) }.joined()
            let runKey = "manual-run-sha256-\(inputSHA)"
            if UserDefaults.standard.bool(forKey: runKey) {
                logger.event("manual_repetition_blocked", details: [
                    "sha256": inputSHA,
                    "reason": "one manual attempt per file"
                ])
                statusLabel.text = "TEST_NOT_STARTED\nCe fichier a déjà été essayé dans cette installation"
                controlButton.isEnabled = true
                manualButton.isEnabled = true
                return
            }
            UserDefaults.standard.set(true, forKey: runKey)
            logger.setState(.testInterrupted, details: [
                "reason": "pre-libarchive marker; not a crash classification",
                "input": destination.lastPathComponent,
                "sha256": inputSHA,
                "manual_attempt_policy": "one attempt per file"
            ])
            let state = renderer.process(url: destination, label: "manual", stateOnPass: .testArchivePass)
            statusLabel.text = message(for: state)
        } catch {
            logger.event("manual_copy_error", details: ["error": String(describing: error)])
            logger.setState(.testArchiveError, details: ["reason": "copy failed"])
            statusLabel.text = "TEST_ARCHIVE_ERROR\nImpossible de copier le fichier"
        }

        controlButton.isEnabled = true
        manualButton.isEnabled = true
    }

    private func message(for state: DiagnosticState) -> String {
        switch state {
        case .testArchivePass:
            return "TEST_ARCHIVE_PASS\nLe fichier a été accepté et parcouru"
        case .longPathControlPass:
            return "LONG_PATH_CONTROL_PASS\nChemin Joliet long accepté dans la limite contrôlée"
        case .testArchiveRejected:
            return "TEST_ARCHIVE_REJECTED\nRejet contrôlé par libarchive"
        case .testArchiveError:
            return "TEST_ARCHIVE_ERROR\nErreur contrôlée de diagnostic"
        default:
            return state.rawValue
        }
    }

    @objc private func exportLogs() {
        logger.event("log_export_requested")
        let controller = UIActivityViewController(activityItems: [logger.logFileURL, logger.stateFileURL], applicationActivities: nil)
        present(controller, animated: true)
    }

    private func configure(_ button: UIButton, title: String, action: Selector) {
        button.setTitle(title, for: .normal)
        button.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        button.addTarget(self, action: action, for: .touchUpInside)
        button.heightAnchor.constraint(equalToConstant: 48).isActive = true
    }
}
