package xyz.rayfish.android.ui.screens

import androidx.compose.runtime.Composable
import uniffi.ray_mobile.NetworkDetail
import uniffi.ray_mobile.Status

@Composable
fun NetworksScreen(
    status: Status?,
    starting: Boolean,
    onToast: (String) -> Unit,
    onChanged: () -> Unit,
    onOpen: (NetworkDetail) -> Unit,
) {}
