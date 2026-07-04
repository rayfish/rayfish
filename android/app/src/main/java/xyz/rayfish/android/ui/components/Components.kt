package xyz.rayfish.android.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.res.painterResource
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import xyz.rayfish.android.ui.theme.Chakra
import xyz.rayfish.android.ui.theme.PlexMono
import xyz.rayfish.android.ui.theme.PressStart
import xyz.rayfish.android.ui.theme.Rf

@Composable
fun BrandHeader(title: String? = null, actions: @Composable RowScope.() -> Unit = {}) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (title == null) {
            Image(
                painter = painterResource(xyz.rayfish.android.R.mipmap.ic_brand),
                contentDescription = "Rayfish",
                modifier = Modifier.size(26.dp).clip(RoundedCornerShape(7.dp)),
            )
            Spacer(Modifier.width(9.dp))
            Text("Rayfish", fontFamily = PressStart, fontSize = 12.sp, color = Rf.Heading)
        } else {
            Text(title, fontFamily = Chakra, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = Rf.Heading)
        }
        Spacer(Modifier.weight(1f))
        actions()
    }
}

@Composable
fun StatusEyebrow(connected: Boolean, text: String) {
    val c = if (connected) Rf.Emerald else Rf.Rose400
    Row(
        Modifier.fillMaxWidth().padding(bottom = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(c))
        Spacer(Modifier.width(7.dp))
        Text(text.uppercase(), fontFamily = PlexMono, fontSize = 10.sp, letterSpacing = 2.sp, color = c)
    }
}

@Composable
fun SectionCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = Rf.Card,
        shape = RoundedCornerShape(15.dp),
        border = BorderStroke(1.dp, Rf.CardBorder),
    ) { Column(Modifier.padding(14.dp), content = content) }
}

@Composable
fun SectionLabel(text: String) {
    Text(
        text.uppercase(), fontFamily = PlexMono, fontSize = 9.sp, letterSpacing = 2.sp,
        color = Rf.Faint, modifier = Modifier.padding(bottom = 8.dp),
    )
}

@Composable
fun KeyValueRow(key: String, value: String, onClick: (() -> Unit)? = null) {
    val base = Modifier.fillMaxWidth().padding(top = 6.dp)
    val rowMod = if (onClick != null) base.clip(RoundedCornerShape(6.dp)).clickable(onClick = onClick) else base
    Row(rowMod, verticalAlignment = Alignment.CenterVertically) {
        Text(key, fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
        Spacer(Modifier.width(12.dp))
        Text(
            value, fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Body,
            maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.End,
            modifier = Modifier.weight(1f),
        )
        if (onClick != null) {
            Spacer(Modifier.width(6.dp))
            Icon(Icons.Filled.ContentCopy, "Copy", tint = Rf.Faint, modifier = Modifier.size(13.dp))
        }
    }
}

@Composable
fun PillButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    Button(
        onClick = onClick, enabled = enabled, modifier = modifier,
        shape = RoundedCornerShape(999.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Rf.Primary, contentColor = Rf.OnPrimary),
    ) { Text(text, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp) }
}

@Composable
fun OutlinePillButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    OutlinedButton(
        onClick = onClick, enabled = enabled, modifier = modifier,
        shape = RoundedCornerShape(999.dp),
        border = BorderStroke(1.dp, Rf.CardBorder),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = Rf.Body),
    ) { Text(text, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp) }
}

@Composable
fun DestructiveTextButton(text: String, onClick: () -> Unit) {
    TextButton(onClick = onClick, colors = ButtonDefaults.textButtonColors(contentColor = Rf.Rose400)) {
        Text(text, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
    }
}

@Composable
fun RayfishTextField(value: String, onValueChange: (String) -> Unit, label: String, modifier: Modifier = Modifier) {
    OutlinedTextField(
        value = value, onValueChange = onValueChange, label = { Text(label, fontFamily = PlexMono, fontSize = 12.sp) },
        singleLine = true, modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(11.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Rf.Rose500, unfocusedBorderColor = Rf.CardBorder,
            focusedTextColor = Rf.Body, unfocusedTextColor = Rf.Body,
            focusedLabelColor = Rf.Rose400, unfocusedLabelColor = Rf.Faint,
            cursorColor = Rf.Rose500,
        ),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RayfishDropdown(
    value: String,
    options: List<String>,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }, modifier = modifier) {
        OutlinedTextField(
            value = value, onValueChange = {}, readOnly = true,
            label = { Text(label, fontFamily = PlexMono, fontSize = 12.sp) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            singleLine = true,
            modifier = Modifier.menuAnchor(MenuAnchorType.PrimaryNotEditable).fillMaxWidth(),
            shape = RoundedCornerShape(11.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Rf.Rose500, unfocusedBorderColor = Rf.CardBorder,
                focusedTextColor = Rf.Body, unfocusedTextColor = Rf.Body,
                focusedLabelColor = Rf.Rose400, unfocusedLabelColor = Rf.Faint,
                focusedTrailingIconColor = Rf.Rose400, unfocusedTrailingIconColor = Rf.Faint,
            ),
        )
        ExposedDropdownMenu(
            expanded = expanded, onDismissRequest = { expanded = false },
            containerColor = Color(0xFF27272A),
        ) {
            options.forEach { opt ->
                DropdownMenuItem(
                    text = { Text(opt, fontFamily = PlexMono, fontSize = 13.sp, color = Rf.Body) },
                    onClick = { onValueChange(opt); expanded = false },
                )
            }
        }
    }
}

@Composable
fun ToggleCard(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    SectionCard {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Column {
                Text(title, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                Text(subtitle, fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Muted, modifier = Modifier.padding(top = 3.dp))
            }
            Switch(
                checked = checked, onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White, checkedTrackColor = Rf.Emerald,
                    uncheckedThumbColor = Color.White, uncheckedTrackColor = Rf.Faint,
                    checkedBorderColor = Color.Transparent, uncheckedBorderColor = Color.Transparent,
                ),
            )
        }
    }
}

data class MenuItem(val label: String, val destructive: Boolean = false, val onClick: () -> Unit)

@Composable
fun OverflowMenu(items: List<MenuItem>, header: String? = null) {
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }) {
            Icon(Icons.Filled.MoreVert, contentDescription = "More", tint = Rf.Muted)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }, containerColor = Color(0xFF27272A)) {
            if (header != null) {
                Text(
                    header, fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Muted,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
                HorizontalDivider(color = Rf.Faint.copy(alpha = 0.2f))
            }
            items.forEach { item ->
                DropdownMenuItem(
                    text = { Text(item.label, fontFamily = Chakra, fontSize = 13.sp, color = if (item.destructive) Rf.Rose400 else Rf.Body) },
                    onClick = { open = false; item.onClick() },
                )
            }
        }
    }
}

@androidx.compose.ui.tooling.preview.Preview(backgroundColor = 0xFF18181B, showBackground = true)
@Composable
private fun ComponentsPreview() {
    xyz.rayfish.android.ui.theme.RayfishTheme {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            BrandHeader()
            StatusEyebrow(connected = true, text = "Connected · 3 networks")
            ToggleCard("Tunnel", "running · 100.88.0.3", checked = true, onCheckedChange = {})
            SectionCard { SectionLabel("Status"); KeyValueRow("IPv4", "100.88.0.3") }
            PillButton("Create network", onClick = {}, modifier = Modifier.fillMaxWidth())
            OutlinePillButton("Join", onClick = {}, modifier = Modifier.fillMaxWidth())
        }
    }
}
