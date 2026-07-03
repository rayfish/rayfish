package xyz.rayfish.android.ui.screens

import androidx.compose.runtime.Composable
import uniffi.ray_mobile.NetworkDetail

@Composable
fun NetworkDetailScreen(
    detail: NetworkDetail,
    onBack: () -> Unit,
    onToast: (String) -> Unit,
    onChanged: () -> Unit,
    onLeft: () -> Unit,
) {}
