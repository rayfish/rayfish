package xyz.rayfish.android.ui

import android.app.Application
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import uniffi.ray_mobile.Status
import uniffi.ray_mobile.Transfer
import uniffi.ray_mobile.TransferState
import xyz.rayfish.android.R
import xyz.rayfish.android.ui.screens.HomeScreen
import xyz.rayfish.android.ui.theme.RayfishTheme

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = Application::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class FileTransfersUiTest {
    @get:Rule val compose = createComposeRule()
    private val app = RuntimeEnvironment.getApplication() as Application

    @Test fun incomingTransferShowsProgressWithoutCancel() {
        showTransfer(outgoing = false, state = TransferState.TRANSFERRING)
        compose.onNodeWithText(app.getString(R.string.file_transfer_bytes, "50 B", "100 B")).assertExists()
        compose.onNodeWithText(app.getString(R.string.action_cancel)).assertDoesNotExist()
    }

    @Test fun outgoingTransferKeepsCancelUntilItFinishes() {
        val state = mutableStateOf(TransferState.OFFERED)
        compose.setContent { RayfishTheme { HomeScreen(snapshot(true, state.value), false, {}) } }
        compose.onNodeWithText(app.getString(R.string.action_cancel)).assertExists()
        compose.runOnIdle { state.value = TransferState.TRANSFERRING }
        compose.onNodeWithText(app.getString(R.string.action_cancel)).assertExists()
        for (terminal in listOf(TransferState.DONE, TransferState.FAILED)) {
            compose.runOnIdle { state.value = terminal }
            compose.onNodeWithText(app.getString(R.string.action_cancel)).assertDoesNotExist()
        }
    }

    private fun showTransfer(outgoing: Boolean, state: TransferState) {
        compose.setContent { RayfishTheme { HomeScreen(snapshot(outgoing, state), false, {}) } }
    }

    private fun snapshot(outgoing: Boolean, state: TransferState) = AppSnapshot(
        status = Status(false, "device", "", emptyList(), emptyList(), emptyList()),
        transfers = listOf(Transfer(1uL, outgoing, "peer", "file.txt", 100uL, 50uL, state)),
        loaded = true,
    )
}
