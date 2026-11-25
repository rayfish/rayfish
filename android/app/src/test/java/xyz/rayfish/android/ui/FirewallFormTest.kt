package xyz.rayfish.android.ui

import android.app.Application
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import uniffi.ray_mobile.FirewallRuleInfo
import uniffi.ray_mobile.FirewallStateInfo
import uniffi.ray_mobile.NetworkConnState
import uniffi.ray_mobile.NetworkDetail
import uniffi.ray_mobile.NetworkFirewallInfo
import uniffi.ray_mobile.NoPointer
import uniffi.ray_mobile.Node
import uniffi.ray_mobile.PeerConnState
import uniffi.ray_mobile.PeerInfo
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.ui.screens.FirewallScreen
import xyz.rayfish.android.ui.screens.NetworkDetailScreen
import xyz.rayfish.android.ui.theme.RayfishTheme

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = Application::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class FirewallFormTest {
    @get:Rule val compose = createComposeRule()
    private val app = RuntimeEnvironment.getApplication() as Application
    private val peerId = "0123456789abcdef"
    private val nodeField = NodeHolder::class.java.getDeclaredField("node").apply { isAccessible = true }
    private var previousNode: Any? = null

    private data class AddedRule(val protocol: String, val port: String?, val peer: String?, val network: String?)
    @Volatile private var addedRule: AddedRule? = null
    @Volatile private var removedIndex: UInt? = null
    @Volatile private var enabledSet: Boolean? = null
    @Volatile private var outboundDefaultSet: String? = null
    @Volatile private var acceptedSuggestionsFor: String? = null
    @Volatile private var firewallState = FirewallStateInfo("deny", "allow", false, emptyList())

    private val fakeNode = object : Node(NoPointer) {
        override fun firewallShow() = firewallState
        override fun firewallAdd(direction: String, action: String, protocol: String, port: String?, peer: String?, network: String?) {
            addedRule = AddedRule(protocol, port, peer, network)
        }
        override fun firewallRemove(index: UInt) {
            removedIndex = index
        }
        override fun firewallSetEnabled(enabled: Boolean) {
            enabledSet = enabled
            firewallState = firewallState.copy(disabled = !enabled)
        }
        override fun firewallSetDefaultOutbound(action: String) {
            outboundDefaultSet = action
            firewallState = firewallState.copy(defaultOutbound = action)
        }
        override fun firewallAcceptSuggestions(network: String) {
            acceptedSuggestionsFor = network
        }
    }

    @Before fun setUp() {
        addedRule = null
        removedIndex = null
        enabledSet = null
        outboundDefaultSet = null
        acceptedSuggestionsFor = null
        firewallState = FirewallStateInfo("deny", "allow", false, emptyList())
        previousNode = nodeField.get(null)
        nodeField.set(null, fakeNode)
    }

    @After fun tearDown() {
        nodeField.set(null, previousNode)
        fakeNode.close()
    }

    @Test fun restoredRuleKeepsItsPeerRestriction() {
        val restore = StateRestorationTester(compose)
        val detail = NetworkDetail("example", "", "phone", false,
            listOf(PeerInfo("", peerId, "build-box", PeerConnState.IDLE)),
            NetworkConnState.CONNECTED, null)
        restore.setContent { RayfishTheme { NetworkDetailScreen(detail, {}, {}, {}, {}) } }
        compose.waitForIdle()
        compose.onNodeWithText(app.getString(R.string.allow_inbound_add)).performScrollTo().performClick()
        compose.onNodeWithText(app.getString(R.string.fw_any_peer)).performClick()
        compose.onNodeWithText("build-box · 0123").performClick()
        compose.onNodeWithText(app.getString(R.string.hint_port)).performTextInput("443")
        restore.emulateSavedInstanceStateRestore()
        compose.onNodeWithText("build-box · 0123").assertExists()
        compose.onNodeWithText("443").assertExists()
        compose.onNodeWithText(app.getString(R.string.action_add_rule)).performClick()
        compose.waitUntil { addedRule != null }
        assertEquals(AddedRule("tcp", "443", peerId, "example"), addedRule)
    }

    @Test fun networkDetailFiltersRulesToCurrentNetworkAndPreservesGlobalIndex() {
        firewallState = FirewallStateInfo(
            defaultInbound = "deny",
            defaultOutbound = "allow",
            disabled = false,
            rules = listOf(
                FirewallRuleInfo("in", "allow", "tcp", "22", "any", "alpha"),
                FirewallRuleInfo("in", "allow", "tcp", "80", "any", "any"),
                FirewallRuleInfo("out", "deny", "tcp", "9000", peerId, "example"),
                FirewallRuleInfo("in", "allow", "udp", "53", peerId, "example"),
            ),
        )
        val detail = NetworkDetail(
            "example", "", "phone", false,
            listOf(PeerInfo("", peerId, "build-box", PeerConnState.IDLE)),
            NetworkConnState.CONNECTED, null,
        )
        compose.setContent { RayfishTheme { NetworkDetailScreen(detail, {}, {}, {}, {}) } }
        compose.waitForIdle()
        compose.onNodeWithText("allow tcp:22").assertDoesNotExist()
        compose.onNodeWithText("allow tcp:80").assertDoesNotExist()
        compose.onNodeWithText("deny tcp:9000").performScrollTo().assertExists()
        compose.onNodeWithText("allow udp:53").performScrollTo().assertExists()
        compose.onAllNodesWithText(app.getString(R.string.action_remove))[0].performScrollTo().performClick()
        compose.waitUntil { removedIndex != null }
        assertEquals(2u, removedIndex)
    }

    @Test fun firewallScreenShowsGeneralRulesTogglesPostureAndAcceptsSuggestions() {
        firewallState = FirewallStateInfo(
            defaultInbound = "deny",
            defaultOutbound = "allow",
            disabled = true,
            rules = listOf(
                FirewallRuleInfo("in", "allow", "tcp", "22", "any", "any", suggestedBy = "ssh"),
                FirewallRuleInfo("out", "deny", "udp", "53", "any", "any"),
                FirewallRuleInfo("in", "allow", "tcp", "443", peerId, "example"),
            ),
            reject = false,
            networks = listOf(
                NetworkFirewallInfo(
                    network = "example",
                    autoAccept = false,
                    pendingRules = listOf(
                        FirewallRuleInfo("in", "allow", "tcp", "8443", "any", "example", suggestedBy = "coord"),
                    ),
                ),
            ),
        )
        val detail = NetworkDetail(
            "example", "", "phone", false,
            listOf(PeerInfo("", peerId, "build-box", PeerConnState.IDLE)),
            NetworkConnState.CONNECTED, null,
            pendingSuggestions = 1u,
        )
        val status = Status(true, "node", "200::1", emptyList(), listOf(detail), emptyList(), null)
        compose.setContent { RayfishTheme { FirewallScreen(status = status, onBack = {}, onToast = {}) } }
        compose.waitForIdle()

        compose.onNodeWithText("allow tcp:22").assertExists()
        compose.onNodeWithText(app.getString(R.string.fw_managed_by_ssh)).assertExists()
        compose.onNodeWithText("deny udp:53").assertExists()
        compose.onNodeWithText("allow tcp:443").assertDoesNotExist()

        compose.onNodeWithText(app.getString(R.string.fw_action_resume)).performClick()
        compose.waitUntil { enabledSet == true }
        assertEquals(true, enabledSet)

        compose.onNodeWithText(app.getString(R.string.fw_toggle_edit, "allow")).performClick()
        compose.onNodeWithText(app.getString(R.string.action_continue)).performClick()
        compose.waitUntil { outboundDefaultSet == "deny" }
        assertEquals("deny", outboundDefaultSet)

        compose.onNodeWithText(app.getString(R.string.action_remove)).performScrollTo().performClick()
        compose.waitUntil { removedIndex != null }
        assertEquals(1u, removedIndex)

        compose.onNodeWithText(app.getString(R.string.fw_accept_suggestions)).performScrollTo().performClick()
        compose.waitUntil { acceptedSuggestionsFor != null }
        assertEquals("example", acceptedSuggestionsFor)
    }

    @Test fun firewallScreenShowsOrphanedNetworkRulesWhenNoNetworksRemain() {
        firewallState = FirewallStateInfo(
            defaultInbound = "deny",
            defaultOutbound = "allow",
            disabled = false,
            rules = listOf(
                FirewallRuleInfo("in", "allow", "tcp", "9090", "any", "removed-net"),
            ),
        )
        val status = Status(true, "node", "200::1", emptyList(), emptyList(), emptyList(), null)
        compose.setContent { RayfishTheme { FirewallScreen(status = status, onBack = {}, onToast = {}) } }
        compose.waitForIdle()
        compose.onNodeWithText("allow tcp:9090").assertExists()
    }
}
