package uz.millygram.app.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.theme

/**
 * The floating notice that a message arrived while you were reading further up.
 *
 * It only exists when it has to. Scrolling the thread out from under somebody
 * who is reading old messages is the thing this avoids — a jump to the bottom
 * mid-sentence loses their place and there is no way back to it. So when the
 * view is already at the bottom the thread simply follows the new message, and
 * when it is not, nothing moves and this appears instead.
 *
 * It carries the sender and a snippet rather than a count, because the decision
 * it is asking for — interrupt what you are reading, or not — depends on who it
 * is from and what it says.
 */
@Composable
fun NewMessagePill(
    visible: Boolean,
    /** What the message said, already truncated by the caller. */
    preview: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    AnimatedVisibility(
        visible = visible,
        // Rises from below and settles, rather than fading in place: it came
        // from the bottom of the thread and the motion says so.
        enter = slideInVertically(tween(320, easing = FastOutSlowInEasing)) { it } +
            fadeIn(tween(220)) + scaleIn(tween(320, easing = FastOutSlowInEasing), initialScale = 0.88f),
        exit = slideOutVertically(tween(200)) { it / 2 } + fadeOut(tween(160)) +
            scaleOut(tween(200), targetScale = 0.9f),
        modifier = modifier,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier
                .liquidGlow(corner = 22.dp)
                .clip(RoundedCornerShape(22.dp))
                .background(theme.surfaceRaised)
                .clickable(onClick = onClick)
                .padding(horizontal = 16.dp, vertical = 11.dp),
        ) {
            ChevronDownGlyph(theme.accent)
            Text(
                text = preview,
                style = MillyType.Meta.copy(fontWeight = FontWeight.Medium),
                color = theme.textPrimary,
                maxLines = 1,
            )
        }
    }
}
