package xyz.rayfish.android.ui

import android.app.Application
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createComposeRule
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
import uniffi.ray_mobile.FirewallStateInfo
import uniffi.ray_mobile.NetworkConnState
import uniffi.ray_mobile.NetworkDetail
import uniffi.ray_mobile.NoPointer
import uniffi.ray_mobile.Node
import uniffi.ray_mobile.PeerConnState
import uniffi.ray_mobile.PeerInfo
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
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
    private val fakeNode = object : Node(NoPointer) {
        override fun firewallShow() = FirewallStateInfo("deny", "allow", false, emptyList())
        override fun firewallAdd(direction: String, action: String, protocol: String, port: String?, peer: String?, network: String?) {
            addedRule = AddedRule(protocol, port, peer, network)
        }
    }

    @Before fun setUp() {
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
}
