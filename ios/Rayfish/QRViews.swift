import AVFoundation
import CoreImage.CIFilterBuiltins
import SwiftUI

struct SharedCode: Identifiable {
    var title: String
    var code: String
    var id: String { code }
}

/// A code to show another device: as a QR code to scan, or text to copy.
struct CodeSheet: View {
    var code: SharedCode
    @State private var copied = false
    private let image: UIImage?

    init(code: SharedCode) {
        self.code = code
        image = QRCode.image(code.code)
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                SectionLabel(code.title)
                if let image {
                    Image(uiImage: image).interpolation(.none).resizable()
                        .frame(width: 220, height: 220)
                        .padding(10).background(Color.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .accessibilityLabel("QR code")
                }
                Text(code.code).font(Rf.mono(12)).foregroundStyle(Rf.muted)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                PillButton(copied ? "Copied" : "Copy code") {
                    copyToClipboard(code.code)
                    copied = true
                }
                ShareLink(item: code.code) {
                    Text("Share").font(Rf.semibold(14)).frame(maxWidth: .infinity, minHeight: 40)
                }
                .buttonStyle(PillStyle(outline: true))
            }
            .padding(20)
        }
        .rayfishPage()
        .presentationDetents([.large])
        .task(id: copied) {
            guard copied else { return }
            try? await Task.sleep(for: .seconds(2))
            copied = false
        }
    }
}

enum QRCode {
    private static let context = CIContext()

    static func image(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage,
              let cgImage = context.createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

/// Scans one QR code with the camera. Without a camera (the simulator) it
/// offers the clipboard instead.
struct QRScannerSheet: View {
    var onCode: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var denied = false

    var body: some View {
        NavigationStack {
            Group {
                if AVCaptureDevice.default(for: .video) == nil || denied {
                    VStack(spacing: 14) {
                        Text(denied ? "Rayfish cannot use the camera. Allow it in Settings, or paste the code."
                                    : "No camera available. Paste the code instead.")
                            .font(Rf.text()).foregroundStyle(Rf.muted)
                        PillButton("Paste from clipboard") {
                            if let text = UIPasteboard.general.string { onCode(text) }
                        }
                    }
                    .padding(20)
                } else {
                    QRCameraView(onCode: onCode).ignoresSafeArea()
                }
            }
            .rayfishPage()
            .navigationTitle("Scan a code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
        .task {
            if AVCaptureDevice.authorizationStatus(for: .video) == .notDetermined {
                denied = !(await AVCaptureDevice.requestAccess(for: .video))
            } else {
                denied = AVCaptureDevice.authorizationStatus(for: .video) != .authorized
            }
        }
    }
}

private struct QRCameraView: UIViewControllerRepresentable {
    var onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        ScannerController(onCode: onCode)
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {}
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private let onCode: (String) -> Void
    private var found = false

    init(onCode: @escaping (String) -> Void) {
        self.onCode = onCode
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.layer.bounds
        view.layer.addSublayer(preview)
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        view.layer.sublayers?.first?.frame = view.layer.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.stopRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !found, let code = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        found = true
        onCode(code)
    }
}
