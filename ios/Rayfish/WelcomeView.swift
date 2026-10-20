import SwiftUI

/// First run, before an identity exists. Starting the node mints one, so a
/// restore has to be offered before anything starts it.
struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var restoring = false
    @State private var keychain: [KeychainBackup] = []

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                BrandHeader(title: "Rayfish")
                    .padding(.bottom, 40)
                SectionCard {
                    SectionLabel("This device")
                    Text("Rayfish gives this device an identity of its own. Peers know it by that and nothing else, so it is worth keeping.")
                        .font(Rf.text()).foregroundStyle(Rf.muted)
                    VStack(spacing: 10) {
                        PillButton("Get started") { model.hasIdentity = true }
                        PillButton("Restore a backup", outline: true) { restoring = true }
                    }
                    .padding(.top, 14)
                    Text("Restoring moves an identity from another device, or back from a backup you saved. You will need the password you chose for it.")
                        .font(Rf.text(13)).foregroundStyle(Rf.faint)
                        .padding(.top, 10)
                }
                if !keychain.isEmpty {
                    KeychainRestoreCard(backups: keychain)
                }
            }
            .padding(20)
        }
        .rayfishPage()
        .sheet(isPresented: $restoring) { RestoreSheet() }
        .task { keychain = await Task.detached { IdentityKeychain.list() }.value }
    }
}
