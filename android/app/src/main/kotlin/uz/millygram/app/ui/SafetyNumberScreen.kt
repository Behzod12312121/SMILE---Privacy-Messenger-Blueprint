package uz.millygram.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * The safety number.
 *
 * Every messenger that has this screen buries it and renders the digits as an
 * undifferentiated wall, which is why almost nobody ever compares one. The
 * number is the only defence against a relay substituting a key, so here it
 * gets a whole screen, grouped into readable blocks at a size two people can
 * actually read to each other across a table.
 *
 * The instruction is phrased as an action rather than a warning. "Compare these
 * with Gʻayrat" is something a person can do; "verify the safety number" is
 * jargon that gets skipped.
 */
@Composable
fun SafetyNumberScreen(
    peerAci: String,
    /** Full name, so the avatar initials match the rest of the app. */
    peerName: String,
    /** Just the given name, because the instruction reads as a sentence. */
    peerGivenName: String,
    safetyNumber: String,
    verified: Boolean,
    onBack: () -> Unit,
    onMarkVerified: () -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(theme.surface)
            .statusBarsPadding(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 6.dp).height(Space.minTouchTarget),
        ) {
            Box(
                Modifier.size(Space.minTouchTarget).clickable(onClick = onBack),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.ArrowBack, "Orqaga", tint = theme.accent, modifier = Modifier.size(24.dp))
            }
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = Space.gutter),
        ) {
            Spacer(Modifier.weight(1f))
            Avatar(peerAci, peerName, 72.dp)
            Spacer(Modifier.height(Space.lg))

            Text(
                "Xavfsizlik raqami",
                style = MillyType.LargeTitle.copy(textAlign = TextAlign.Center),
                color = theme.textPrimary,
            )
            Spacer(Modifier.height(Space.sm))
            Text(
                "Bu raqamlarni $peerGivenName bilan solishtiring. Ikkalangizda bir xil " +
                    "boʻlsa, suhbatingizni hech kim oʻzgartira olmagan.",
                style = MillyType.Notice.copy(textAlign = TextAlign.Center, lineHeight = 20.sp),
                color = theme.textSecondary,
                modifier = Modifier.padding(horizontal = Space.sm),
            )

            Spacer(Modifier.height(Space.xxl))
            FingerprintGrid(safetyNumber)
            Spacer(Modifier.height(Space.xl))

            if (verified) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(Space.sm),
                    modifier = Modifier
                        .clip(RoundedCornerShape(Radius.card))
                        .background(theme.accentMuted)
                        .padding(horizontal = Space.lg, vertical = Space.md),
                ) {
                    ShieldGlyph(theme.verified, size = 18.dp)
                    Text("Tasdiqlangan", style = MillyType.Label, color = theme.verified)
                }
            }
            Spacer(Modifier.weight(1.25f))
        }

        Box(
            Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = Space.gutter)
                .padding(bottom = Space.xl, top = Space.md),
        ) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(if (verified) theme.field else theme.accent)
                    .clickable(onClick = onMarkVerified)
                    .padding(vertical = 15.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (verified) "Tasdiqni bekor qilish" else "Tasdiqlandi deb belgilash",
                    style = MillyType.Label,
                    color = if (verified) theme.textSecondary else theme.onAccent,
                )
            }
        }
    }
}

/**
 * Sixty digits in twelve groups of five, four to a row.
 *
 * The grouping is what makes the number readable aloud. A flat sixty-character
 * string is impossible to keep your place in; five-digit blocks are the same
 * unit people already use for phone numbers and card numbers.
 */
@Composable
private fun FingerprintGrid(safetyNumber: String) {
    val digits = safetyNumber.filter { it.isDigit() }
    val groups = digits.chunked(5)

    Column(
        verticalArrangement = Arrangement.spacedBy(Space.xs),
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(Radius.card))
            .background(theme.surfaceRaised)
            .padding(vertical = Space.xl, horizontal = Space.md),
    ) {
        groups.chunked(4).forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(Space.md)) {
                row.forEach { group ->
                    Text(group, style = MillyType.Fingerprint, color = theme.textPrimary)
                }
            }
        }
    }
}
