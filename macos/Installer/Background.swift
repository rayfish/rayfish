import AppKit
import CoreText

// Render from the app's fonts and logo so the installer follows the same theme.
guard CommandLine.arguments.count == 3 else {
  fatalError("Usage: swift Background.swift <repository> <output.tiff>")
}
let root = URL(fileURLWithPath: CommandLine.arguments[1])
let output = URL(fileURLWithPath: CommandLine.arguments[2])
let width = 720
let height = 480
for name in [
  "ChakraPetch-Regular", "ChakraPetch-SemiBold", "PressStart2P-Regular", "IBMPlexMono-Regular",
] {
  let url = root.appendingPathComponent("macos/Rayfish/Fonts/\(name).ttf")
  CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
}

func color(_ hex: UInt32) -> NSColor {
  NSColor(
    srgbRed: CGFloat((hex >> 16) & 255) / 255,
    green: CGFloat((hex >> 8) & 255) / 255,
    blue: CGFloat(hex & 255) / 255, alpha: 1)
}

func rect(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat) -> NSRect {
  NSRect(x: x, y: CGFloat(height) - y - h, width: w, height: h)
}

func text(
  _ value: String, x: CGFloat, y: CGFloat, width: CGFloat,
  font name: String, size: CGFloat, ink: UInt32, centered: Bool = false
) {
  let paragraph = NSMutableParagraphStyle()
  paragraph.alignment = centered ? .center : .left
  let attributes: [NSAttributedString.Key: Any] = [
    .font: NSFont(name: name, size: size)!,
    .foregroundColor: color(ink),
    .paragraphStyle: paragraph,
  ]
  (value as NSString).draw(in: rect(x, y, width, 60), withAttributes: attributes)
}

func render(scale: Int) -> NSBitmapImageRep {
  let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: width * scale, pixelsHigh: height * scale,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
    isPlanar: false, colorSpaceName: .deviceRGB,
    bytesPerRow: 0, bitsPerPixel: 0)!
  bitmap.size = NSSize(width: width, height: height)
  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
  color(0x18181b).setFill()
  NSBezierPath(rect: rect(0, 0, 720, 480)).fill()

  // A restrained accent and a mesh motif leave the Finder icons easy to read.
  color(0xf43f5e).setFill()
  NSBezierPath(rect: rect(0, 0, 720, 3)).fill()
  color(0x27272a).setStroke()
  for index in 0..<5 {
    let path = NSBezierPath()
    path.move(to: NSPoint(x: 475 + index * 38, y: 480))
    path.line(to: NSPoint(x: 720, y: 340 - index * 24))
    path.lineWidth = 1
    path.stroke()
  }

  let logo = NSImage(
    contentsOf: root.appendingPathComponent("macos/Rayfish/Assets.xcassets/Logo.imageset/logo.png"))!
  logo.draw(in: rect(48, 35, 44, 44))
  text("rayfish", x: 108, y: 44, width: 260, font: "PressStart2P-Regular", size: 23, ink: 0xf4f4f5)
  text(
    "PRIVATE MESH", x: 507, y: 49, width: 165, font: "IBMPlexMono-Regular", size: 12, ink: 0xa1a1aa)
  text(
    "Your network. Everywhere.", x: 48, y: 112, width: 624,
    font: "ChakraPetch-SemiBold", size: 29, ink: 0xf4f4f5)
  text(
    "Install Rayfish to connect this Mac to your private networks.",
    x: 48, y: 155, width: 624, font: "ChakraPetch-Regular", size: 16, ink: 0xa1a1aa)

  for x: CGFloat in [132, 452] {
    color(0xe4e4e7).setFill()
    let well = NSBezierPath(roundedRect: rect(x, 210, 136, 154), xRadius: 28, yRadius: 28)
    well.fill()
    color(0xf4f4f5).setStroke()
    well.lineWidth = 1
    well.stroke()
  }
  let connector = NSBezierPath()
  connector.move(to: NSPoint(x: 310, y: CGFloat(height) - 275))
  connector.line(to: NSPoint(x: 410, y: CGFloat(height) - 275))
  connector.move(to: NSPoint(x: 400, y: CGFloat(height) - 265))
  connector.line(to: NSPoint(x: 410, y: CGFloat(height) - 275))
  connector.line(to: NSPoint(x: 400, y: CGFloat(height) - 285))
  connector.lineWidth = 2
  color(0xfb7185).setStroke()
  connector.stroke()

  text(
    "Drag Rayfish into Applications", x: 48, y: 385, width: 624,
    font: "ChakraPetch-SemiBold", size: 20, ink: 0xf4f4f5, centered: true)
  text(
    "Then open Rayfish from Applications to get started.", x: 48, y: 419, width: 624,
    font: "ChakraPetch-Regular", size: 14, ink: 0xa1a1aa, centered: true)
  NSGraphicsContext.restoreGraphicsState()
  return bitmap
}

// Finder chooses the 2x representation on Retina displays without changing the layout size.
let representations = [render(scale: 1), render(scale: 2)]
try NSBitmapImageRep.representationOfImageReps(in: representations, using: .tiff, properties: [:])!
  .write(to: output)
