package uz.millygram.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * What sits in front of the conversations while the app is locked.
 *
 * Deliberately blank of content. The point of this screen is that somebody
 * holding the phone learns nothing from it, so there is no contact list behind
 * a blur, no unread count, no last-message preview — the things other apps leak
 * on their own lock screens without noticing.
 */
@Composable
fun LockedScreen(
    /** Set when the prompt could not run, rather than when it was dismissed. */
    error: String?,
    onUnlock: () -> Unit,
    /**
     * Closes the session and falls back to the passphrase.
     *
     * There has to be one of these. A gate whose only control retries a sensor
     * that has stopped working — re-enrolled, worn out, locked out after too
     * many bad reads, or simply never present on the host that composed this —
     * is a gate that has taken the account with it, and this app already tells
     * people the passphrase is the way back in. Deliberately not a silent
     * bypass: it shuts the conversations first and then asks for the thing the
     * user knows, so the way round the fingerprint is strictly harder than the
     * fingerprint, never easier.
     */
    onUsePassphrase: () -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(theme.background)
            .padding(horizontal = Space.gutter),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier.size(76.dp).clip(RoundedCornerShape(24.dp)).background(theme.accentMuted),
            contentAlignment = Alignment.Center,
        ) {
            LockGlyph(theme.accent, size = 34.dp)
        }

        Spacer(Modifier.height(Space.xl))
        Text("Smile qulflangan", style = MillyType.LargeTitle, color = theme.textPrimary)
        Spacer(Modifier.height(Space.sm))
        Text(
            "Suhbatlarni koʻrish uchun barmoq izingiz yoki qurilma kodi kerak.",
            style = MillyType.Notice,
            color = theme.textSecondary,
            textAlign = TextAlign.Center,
        )

        if (error != null) {
            Spacer(Modifier.height(Space.lg))
            Text(error, style = MillyType.Timestamp, color = theme.noticeStrong, textAlign = TextAlign.Center)
        }

        Spacer(Modifier.height(Space.xxl))
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(theme.accent)
                .clickable(onClick = onUnlock)
                .padding(vertical = 15.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text("Ochish", style = MillyType.Label, color = theme.onAccent)
        }

        Spacer(Modifier.height(Space.sm))
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .clickable(onClick = onUsePassphrase)
                .padding(vertical = 15.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text("Parol bilan kirish", style = MillyType.Label, color = theme.accent)
        }
    }
}
