import Foundation
import UIKit
import UniformTypeIdentifiers
import CryptoKit

private enum DiagnosticState: String {
    case testNotStarted = "TEST_NOT_STARTED"
    case controlArchivePass = "CONTROL_ARCHIVE_PASS"
    case testArchivePass = "TEST_ARCHIVE_PASS"
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
        try? handle.seekToEnd()
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
        var entries: UInt64 = 0
        var bytes: UInt64 = 0

        logger.event("libarchive_start", details: [
            "label": label,
            "api": "dlopen + archive_read_open_filename + archive_read_next_header"
        ])
        let result = url.path.withCString { path in
            kind.withUnsafeMutableBufferPointer { kindBuffer in
                message.withUnsafeMutableBufferPointer { messageBuffer in
                    LAProcessISO(
                        path,
                        kindBuffer.baseAddress,
                        kindBuffer.count,
                        messageBuffer.baseAddress,
                        messageBuffer.count,
                        &entries,
                        &bytes
                    )
                }
            }
        }
        let resultKind = kind.withUnsafeBufferPointer { buffer in
            String(cString: buffer.baseAddress!)
        }
        let resultMessage = message.withUnsafeBufferPointer { buffer in
            String(cString: buffer.baseAddress!)
        }
        logger.event("libarchive_complete", details: [
            "label": label,
            "return_code": result,
            "kind": resultKind,
            "message": resultMessage,
            "entries": entries,
            "bytes": bytes
        ])

        if result == LA_DIAGNOSTIC_PASS {
            logger.setState(stateOnPass, details: ["label": label, "entries": entries])
            return stateOnPass
        }
        if result == LA_DIAGNOSTIC_REJECTED {
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
    private let testRunKey = "CVE-2026-112522.test-run-started"
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
            ? "TEST_INTERRUPTED\nRécupérer le journal et un éventuel .ips avant toute nouvelle installation."
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
        guard !UserDefaults.standard.bool(forKey: testRunKey) else {
            showMessage(title: "Test déjà lancé", message: "Cette installation a déjà traité un fichier manuel. Consultez le journal et un éventuel rapport .ips avant toute nouvelle tentative.")
            return
        }
        logger.event("manual_picker_open")
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        picker.delegate = self
        picker.allowsMultipleSelection = false
        present(picker, animated: true)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let sourceURL = urls.first else { return }
        let alert = UIAlertController(
            title: "Test manuel unique",
            message: "Le fichier choisi sera remis à libarchive une seule fois. L'application ne génère aucun fichier malformé et ne relancera pas le test après une fermeture.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Annuler", style: .cancel))
        alert.addAction(UIAlertAction(title: "Lancer", style: .destructive) { [weak self] _ in
            self?.runManualFile(sourceURL)
        })
        present(alert, animated: true)
    }

    private func runManualFile(_ sourceURL: URL) {
        UserDefaults.standard.set(true, forKey: testRunKey)
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
            logger.setState(.testInterrupted, details: [
                "reason": "pre-libarchive marker; not a crash classification",
                "input": destination.lastPathComponent
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

    private func showMessage(title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    private func configure(_ button: UIButton, title: String, action: Selector) {
        button.setTitle(title, for: .normal)
        button.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        button.addTarget(self, action: action, for: .touchUpInside)
        button.heightAnchor.constraint(equalToConstant: 48).isActive = true
    }
}
