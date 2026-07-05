package ro.sigurscan.app.ui.v2.components

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.DataObject
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Flag
import androidx.compose.material.icons.rounded.PriorityHigh
import androidx.compose.material.icons.rounded.Remove
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ro.sigurscan.app.ui.v2.theme.SigurTokensV2
import ro.sigurscan.app.ui.v2.theme.TypeV2
import ro.sigurscan.app.ui.v2.theme.VerdictPalette
import ro.sigurscan.app.ui.v2.theme.VerdictTone

enum class ReasonSeverity { GOOD, NEUTRAL, ALERT }

data class VerdictReason(val text: String, val severity: ReasonSeverity)

/**
 * The verdict card — themed container + gradient header + reason rows.
 * One component, themed by [tone] (design system §06: "verdictul temează conținutul").
 */
@Composable
fun VerdictCardV2(
    tone: VerdictTone,
    badgeLabel: String,
    title: String,
    subtitle: String,
    headerIcon: ImageVector,
    reasons: List<VerdictReason>,
    modifier: Modifier = Modifier,
    extraHeaderContent: (@Composable () -> Unit)? = null,
) {
    val palette = SigurTokensV2.palette(tone)
    Column(
        modifier = modifier
            .fillMaxWidth()
            .elevatedCardV2(SigurTokensV2.RadiusVerdict)
            .clip(RoundedCornerShape(SigurTokensV2.RadiusVerdict))
            .background(SigurTokensV2.Surface),
    ) {
        VerdictHeaderV2(
            palette = palette,
            badgeLabel = badgeLabel,
            title = title,
            subtitle = subtitle,
            icon = headerIcon,
        )
        extraHeaderContent?.invoke()
        Column(modifier = Modifier.padding(start = 17.dp, end = 17.dp, top = 14.dp, bottom = 17.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.Flag, contentDescription = null, tint = palette.accent, modifier = Modifier.size(14.dp))
                Text(
                    "DE CE SPUNEM ASTA",
                    style = TypeV2.Eyebrow,
                    color = palette.accent,
                    modifier = Modifier.padding(start = 7.dp),
                )
            }
            reasons.forEach { reason ->
                ReasonRowV2(reason = reason, palette = palette, modifier = Modifier.padding(top = 11.dp))
            }
        }
    }
}

@Composable
private fun VerdictHeaderV2(
    palette: VerdictPalette,
    badgeLabel: String,
    title: String,
    subtitle: String,
    icon: ImageVector,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(palette.gradient)
            .padding(18.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(52.dp)
                .clip(CircleShape)
                .background(Color.White.copy(alpha = 0.18f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = null, tint = Color.White, modifier = Modifier.size(27.dp))
        }
        Column(modifier = Modifier.padding(start = 14.dp)) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(SigurTokensV2.RadiusPill))
                    .background(Color.White.copy(alpha = 0.95f))
                    .padding(horizontal = 10.dp, vertical = 3.dp),
            ) {
                Text(
                    badgeLabel,
                    style = TypeV2.Eyebrow.copy(fontSize = 9.5.sp),
                    color = palette.accent,
                )
            }
            Text(
                title,
                style = TypeV2.VerdictHeader,
                color = Color.White,
                modifier = Modifier.padding(top = 7.dp),
            )
            Text(
                subtitle,
                style = TypeV2.Body.copy(color = Color.White.copy(alpha = 0.92f), fontWeight = FontWeight.Medium),
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

@Composable
private fun ReasonRowV2(reason: VerdictReason, palette: VerdictPalette, modifier: Modifier = Modifier) {
    val (icon, tint) = when (reason.severity) {
        ReasonSeverity.GOOD -> Icons.Rounded.Check to SigurTokensV2.Sigur.accent
        ReasonSeverity.NEUTRAL -> Icons.Rounded.Remove to SigurTokensV2.Neverificat.accent
        ReasonSeverity.ALERT -> Icons.Rounded.PriorityHigh to palette.accent
    }
    Row(modifier = modifier.fillMaxWidth()) {
        Box(
            modifier = Modifier
                .size(22.dp)
                .clip(RoundedCornerShape(7.dp))
                .background(tint.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(14.dp))
        }
        Text(
            reason.text,
            style = TypeV2.Body,
            color = SigurTokensV2.Body,
            modifier = Modifier.padding(start = 10.dp),
        )
    }
}

/** "Ce să faci acum" support card — bullet action list + collapsible tech details. */
@Composable
fun ActionPlanCardV2(
    accent: Color,
    icon: ImageVector,
    actions: List<String>,
    techDetails: List<Pair<String, String>>,
    modifier: Modifier = Modifier,
    title: String = "Ce să faci acum",
) {
    CardOutlinedV2(modifier = modifier.fillMaxWidth(), padding = 16.dp) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(18.dp))
            Text(
                title,
                style = TypeV2.CardTitle,
                color = SigurTokensV2.Ink,
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        actions.forEach { action ->
            Row(modifier = Modifier.padding(top = 8.dp)) {
                Text("•", style = TypeV2.Body.copy(color = accent))
                Text(action, style = TypeV2.Body, color = SigurTokensV2.Body, modifier = Modifier.padding(start = 9.dp))
            }
        }
        if (techDetails.isNotEmpty()) {
            TechDetailsV2(techDetails, modifier = Modifier.padding(top = 15.dp))
        }
    }
}

@Composable
private fun TechDetailsV2(rows: List<Pair<String, String>>, modifier: Modifier = Modifier) {
    var expanded by remember { mutableStateOf(false) }
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(SigurTokensV2.Fill)
            .animateContentSize()
            .clickable { expanded = !expanded }
            .padding(horizontal = 13.dp, vertical = 12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Rounded.DataObject,
                    contentDescription = null,
                    tint = SigurTokensV2.Muted,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    "Detalii tehnice",
                    style = TypeV2.CardTitle.copy(fontSize = 14.sp),
                    color = SigurTokensV2.Ink,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            Icon(Icons.Rounded.ExpandMore, contentDescription = null, tint = SigurTokensV2.Muted)
        }
        if (expanded) {
            Column(modifier = Modifier.padding(top = 2.dp)) {
                rows.forEach { (key, value) -> DetailRowV2(key, value) }
            }
        }
    }
}

/** "A fost util acest verdict?" DA/NU feedback row. */
@Composable
fun FeedbackRowV2(onYes: () -> Unit, onNo: () -> Unit, modifier: Modifier = Modifier) {
    Row(modifier = modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(11.dp)) {
        FeedbackPillV2(
            label = "DA",
            color = SigurTokensV2.Sigur.dark,
            bg = SigurTokensV2.Sigur.accent.copy(alpha = 0.08f),
            onClick = onYes,
            modifier = Modifier.weight(1f),
        )
        FeedbackPillV2(
            label = "NU",
            color = SigurTokensV2.Periculos.dark,
            bg = SigurTokensV2.Periculos.accent.copy(alpha = 0.08f),
            onClick = onNo,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun FeedbackPillV2(label: String, color: Color, bg: Color, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(13.dp))
            .background(bg)
            .clickable(onClick = onClick)
            .padding(vertical = 13.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(label, style = TypeV2.CardTitle, color = color)
    }
}
