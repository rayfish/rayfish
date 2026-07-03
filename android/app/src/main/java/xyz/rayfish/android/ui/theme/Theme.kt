package xyz.rayfish.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

@Composable
fun RayfishTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = RayfishColorScheme,
        typography = RayfishTypography,
        content = content,
    )
}
