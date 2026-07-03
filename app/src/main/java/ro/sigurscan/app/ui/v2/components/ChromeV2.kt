package ro.sigurscan.app.ui.v2.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.MoreHoriz
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap
import ro.sigurscan.app.R
import ro.sigurscan.app.ui.v2.theme.SigurTokensV2
import ro.sigurscan.app.ui.v2.theme.TypeV2

/** App header — SigurScan shield logo + wordmark + tagline (v2, top of every screen). */
@Composable
fun AppHeaderV2(modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth().padding(top = 6.dp, bottom = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_sigurscan_logo),
            contentDescription = null,
            modifier = Modifier.size(40.dp),
        )
        Column(modifier = Modifier.padding(start = 12.dp)) {
            Text("SigurScan", style = TypeV2.SectionTitle.copy(fontSize = 22.sp), color = SigurTokensV2.Ink)
            Text("Verifici doar ce alegi tu", style = TypeV2.Caption, color = SigurTokensV2.Muted)
        }
    }
}

enum class BottomNavTabV2 { RADAR, PROTECTIE, SCANEAZA, URGENTA, MAI_MULT }

/** Bottom navigation — 5 tabs, docked central FAB, gradient bar (matches DS §05). */
@Composable
fun BottomNavBarV2(
    selected: BottomNavTabV2,
    onSelect: (BottomNavTabV2) -> Unit,
    modifier: Modifier = Modifier,
    urgentaHasAlert: Boolean = true,
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .padding(horizontal = 16.dp, vertical = 10.dp)
            .height(90.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(64.dp)
                .align(Alignment.BottomCenter)
                .navBarShadowV2(26.dp)
                .clip(RoundedCornerShape(26.dp))
                .background(SigurTokensV2.NavGradient)
                .padding(horizontal = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            NavTabV2(Icons.Rounded.Radar, "Radar", selected == BottomNavTabV2.RADAR, Modifier.weight(1f)) { onSelect(BottomNavTabV2.RADAR) }
            NavTabV2(Icons.Rounded.VerifiedUser, "Protecție", selected == BottomNavTabV2.PROTECTIE, Modifier.weight(1f)) { onSelect(BottomNavTabV2.PROTECTIE) }
            Box(modifier = Modifier.weight(1f), contentAlignment = Alignment.Center) { /* FAB docked below */ }
            NavTabV2(
                icon = Icons.Rounded.Warning,
                label = "Urgență",
                active = selected == BottomNavTabV2.URGENTA,
                modifier = Modifier.weight(1f),
                showAlertDot = urgentaHasAlert,
                onClick = { onSelect(BottomNavTabV2.URGENTA) },
            )
            NavTabV2(Icons.Rounded.MoreHoriz, "Mai mult", selected == BottomNavTabV2.MAI_MULT, Modifier.weight(1f)) { onSelect(BottomNavTabV2.MAI_MULT) }
        }
        Column(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .offset(y = 0.dp)
                .clickable { onSelect(BottomNavTabV2.SCANEAZA) },
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .size(54.dp)
                    .fabShadowV2(54.dp)
                    .clip(CircleShape)
                    .background(Color.White)
                    .border(3.dp, SigurTokensV2.Canvas, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.QrCodeScanner, contentDescription = "Scanează", tint = SigurTokensV2.Sigur.accent, modifier = Modifier.size(25.dp))
            }
            // Label sits on the green pill below the FAB (v2: white, ~10px from pill edge).
            // padding(top) here is measured from the FAB's bottom edge, not the Column top.
            Text(
                "Scanează",
                style = TypeV2.Eyebrow.copy(fontSize = 11.sp, letterSpacing = 0.sp),
                color = Color.White,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
    }
}

@Composable
private fun NavTabV2(
    icon: ImageVector,
    label: String,
    active: Boolean,
    modifier: Modifier = Modifier,
    showAlertDot: Boolean = false,
    onClick: () -> Unit,
) {
    val contentColor = if (active) Color.White else Color.White.copy(alpha = 0.74f)
    Column(
        modifier = modifier.clickable(onClick = onClick),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box {
            Icon(icon, contentDescription = label, tint = contentColor, modifier = Modifier.size(24.dp))
            if (showAlertDot) {
                Box(
                    modifier = Modifier
                        .size(9.dp)
                        .align(Alignment.TopEnd)
                        .offset(x = 4.dp, y = (-2).dp)
                        .clip(CircleShape)
                        .background(Color(0xFFFF5A4D)),
                )
            }
        }
        Text(
            label,
            style = TypeV2.Caption.copy(fontSize = 11.sp, color = contentColor, fontWeight = if (active) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.SemiBold),
            modifier = Modifier.padding(top = 2.dp),
        )
    }
}
