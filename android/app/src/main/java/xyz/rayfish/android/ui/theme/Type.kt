package xyz.rayfish.android.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import xyz.rayfish.android.R

val PressStart = FontFamily(Font(R.font.press_start_2p_regular, FontWeight.Normal))

val Chakra = FontFamily(
    Font(R.font.chakra_petch_regular, FontWeight.Normal),
    Font(R.font.chakra_petch_medium, FontWeight.Medium),
    Font(R.font.chakra_petch_semibold, FontWeight.SemiBold),
    Font(R.font.chakra_petch_bold, FontWeight.Bold),
)

val PlexMono = FontFamily(
    Font(R.font.ibm_plex_mono_regular, FontWeight.Normal),
    Font(R.font.ibm_plex_mono_medium, FontWeight.Medium),
)

/** Chakra Petch body with the site's wide tracking; Material3 slots we use. */
val RayfishTypography = Typography(
    titleLarge = TextStyle(fontFamily = Chakra, fontWeight = FontWeight.Bold, fontSize = 22.sp, letterSpacing = 0.02.em),
    titleMedium = TextStyle(fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, letterSpacing = 0.02.em),
    bodyMedium = TextStyle(fontFamily = Chakra, fontWeight = FontWeight.Normal, fontSize = 14.sp, letterSpacing = 0.02.em),
    labelSmall = TextStyle(fontFamily = PlexMono, fontWeight = FontWeight.Medium, fontSize = 11.sp),
)
