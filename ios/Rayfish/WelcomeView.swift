import SwiftUI

/// First run, before an identity exists. Starting the node mints one, so a
/// restore has to be offered before anything starts it.
struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var restoring = false

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                BrandHeader(title: "Rayfish")
                SectionCard {
                    SectionLabel("This device")
                    Text("Rayfish gives this device an identity of its own. Peers know it by that and nothing else, so it is worth keeping.")
                        .font(Rf.text()).foregroundStyle(Rf.muted)
                    PillButton("Get started") { model.hasIdentity = true }
                        .padding(.top, 10)
                    PillButton("Restore a backup", outline: true) { restoring = true }
                    Text("Restoring moves an identity from another device, or back from a backup you saved. You will need the password you chose for it.")
                        .font(Rf.mono(12)).foregroundStyle(Rf.faint)
                        .padding(.top, 4)
                }
            }
            .padding(20)
        }
        .rayfishPage()
        .sheet(isPresented: $restoring) { RestoreSheet() }
    }
}
