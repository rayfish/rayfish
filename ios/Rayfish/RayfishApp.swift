import SwiftUI

@main
struct RayfishApp: App {
    @StateObject private var model = AppModel()

    init() {
        Telemetry.apply()
        Rf.applyAppearance()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                // Compose's 14sp body text sits on a 20sp line; match it so
                // wrapped text reads the same as on Android.
                .lineSpacing(5)
        }
    }
}

enum Tab: Hashable {
    case networks, home, you
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var tab = Tab.home
    @State private var pendingLink: String?

    var body: some View {
        Group {
            switch model.hasIdentity {
            case nil:
                Color.clear
            case false?:
                WelcomeView()
            case true?:
                tabs
            }
        }
        .rayfishPage()
        .overlay(alignment: .bottom) { ToastView() }
        .task { await model.checkIdentity() }
        .onOpenURL { url in
            pendingLink = url.absoluteString
            followPendingLink()
        }
        .onChange(of: model.hasIdentity) { _, has in
            guard has == true else { return }
            Task {
                await model.launch()
                followPendingLink()
            }
        }
    }

    private var tabs: some View {
        TabView(selection: $tab) {
            NavigationStack { NetworksView() }
                .tabItem { Label("Networks", systemImage: "point.3.connected.trianglepath.dotted") }
                .tag(Tab.networks)
            NavigationStack { HomeView(openNetworks: { tab = .networks }) }
                .tabItem { Label("Home", systemImage: "house.fill") }
                .tag(Tab.home)
            NavigationStack { YouView() }
                .tabItem { Label("You", systemImage: "person.crop.circle.fill") }
                .tag(Tab.you)
        }
        .tint(Rf.rose400)
        // Poll while on screen; iOS suspends the app in the background anyway.
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            while !Task.isCancelled {
                model.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// Deep links wait for the identity gate, like everything that starts the node.
    private func followPendingLink() {
        guard model.hasIdentity == true, let link = pendingLink else { return }
        pendingLink = nil
        Task { await model.perform(.submitCode(link)) }
    }
}

struct ToastView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let toast = model.toast {
            Text(toast)
                .font(Rf.text())
                .foregroundStyle(Rf.heading)
                .padding(.horizontal, 16).padding(.vertical, 12)
                .background(Rf.sheet)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Rf.cardBorder))
                .padding(.horizontal, 20).padding(.bottom, 64)
                .transition(.opacity)
                .onTapGesture { model.toast = nil }
                .task(id: toast) {
                    try? await Task.sleep(for: .seconds(3))
                    if model.toast == toast { model.toast = nil }
                }
        }
    }
}
