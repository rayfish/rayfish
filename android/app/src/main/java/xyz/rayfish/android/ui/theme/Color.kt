package xyz.rayfish.android.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.graphics.Color

/** Exact rayfish.xyz palette. Names mirror the site's zinc/rose/emerald scale. */
object Rf {
    val Bg = Color(0xFF18181B)          // zinc-900
    val Sheet = Color(0xFF1C1C1F)
    val Card = Color(0x8027272A)        // zinc-800 @ 50%
    val CardBorder = Color(0xB33F3F46)  // zinc-700 @ 70%
    val Heading = Color(0xFFF4F4F5)     // zinc-100
    val Body = Color(0xFFD4D4D8)        // zinc-300
    val Muted = Color(0xFFA1A1AA)       // zinc-400
    val Faint = Color(0xFF71717A)       // zinc-500
    val Rose400 = Color(0xFFFB7185)
    val Rose500 = Color(0xFFF43F5E)
    val Rose600 = Color(0xFFE11D48)
    val Emerald = Color(0xFF34D399)     // emerald-400
    val OnPrimary = Color(0xFF18181B)   // text on white pills
    val Primary = Color(0xFFF4F4F5)     // white pill fill
}

val RayfishColorScheme = darkColorScheme(
    primary = Rf.Primary,
    onPrimary = Rf.OnPrimary,
    background = Rf.Bg,
    onBackground = Rf.Body,
    surface = Rf.Bg,
    onSurface = Rf.Body,
    surfaceVariant = Rf.Card,
    onSurfaceVariant = Rf.Muted,
    secondary = Rf.Rose500,
    error = Rf.Rose500,
)
