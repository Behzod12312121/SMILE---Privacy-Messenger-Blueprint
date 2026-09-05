package uz.millygram.app.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.avatarColorFor
import uz.millygram.app.theme.initialsFor
import uz.millygram.app.theme.theme

/**
 * A generated avatar. There are no profile photos anywhere in this app, and
 * that is a security decision rather than an aesthetic one: a photo means an
 * image decoder, and image decoders are where the zero-click exploits in every
 * other messenger have lived.
 *
 * The colour is derived from the account id, so it is stable across devices
 * and needs nothing stored.
 */
@Composable
fun Avatar(
    id: String,
    name: String,
    size: Dp,
    modifier: Modifier = Modifier,
) {
    val fontSize = (size.value * 0.34f).sp
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(avatarColorFor(id)),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = initialsFor(name),
            style = MillyType.Name.copy(fontSize = fontSize, letterSpacing = 0.02.em),
            color = Color.White,
        )
    }
}

/** An uppercase section label. Tracking is wide so it reads as furniture, not content. */
@Composable
fun SectionHeader(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = MillyType.SectionHeader,
        color = theme.textTertiary,
        modifier = modifier.padding(horizontal = Space.gutter, vertical = Space.sm),
    )
}

/** Grouped rows on a raised card — the shape settings screens use throughout. */
@Composable
fun Card(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.lg)
            .clip(RoundedCornerShape(Radius.card))
            .background(theme.surfaceRaised),
    ) { content() }
}

/** The inset separator between rows inside a card. Never used between chat rows. */
@Composable
fun RowSeparator(inset: Dp = 50.dp) {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(start = inset)
            .height(Space.hairline)
            .background(theme.hairline),
    )
}

@Composable
fun SettingsRow(
    label: String,
    modifier: Modifier = Modifier,
    value: String? = null,
    valueColor: Color? = null,
    valueMono: Boolean = false,
    enabled: Boolean = true,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier
            .fillMaxWidth()
            .then(if (onClick != null && enabled) Modifier.clickable(onClick = onClick) else Modifier)
            .defaultMinSize(minHeight = 52.dp)
            .padding(horizontal = Space.lg),
    ) {
        if (leading != null) {
            leading()
            Spacer(Modifier.width(14.dp))
        }
        Text(
            text = label,
            style = MillyType.Label,
            color = if (enabled) theme.textPrimary else theme.textTertiary,
            modifier = Modifier.weight(1f),
        )
        if (value != null) {
            Text(
                text = value,
                style = if (valueMono) MillyType.MonoSmall else MillyType.Meta,
                color = valueColor ?: theme.textTertiary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (trailing != null) {
            Spacer(Modifier.width(Space.sm))
            trailing()
        }
    }
}

/**
 * The toggle. Animated with a spring rather than a linear tween so it feels
 * physical; the difference is small and it is exactly the kind of detail that
 * separates an app that feels considered from one that feels assembled.
 */
@Composable
fun MillyToggle(checked: Boolean, onCheckedChange: ((Boolean) -> Unit)? = null) {
    val progress by animateFloatAsState(
        targetValue = if (checked) 1f else 0f,
        animationSpec = spring(dampingRatio = 0.7f, stiffness = 900f),
        label = "toggle",
    )
    val track = androidx.compose.ui.graphics.lerp(
        if (theme.isDark) Color(0xFF2A3338) else Color(0xFFDDE2E4),
        theme.accent,
        progress,
    )
    val knob = if (theme.isDark && checked) theme.onAccent else Color.White

    Box(
        modifier = Modifier
            .size(width = 50.dp, height = 30.dp)
            .clip(CircleShape)
            .background(track)
            .then(if (onCheckedChange != null) Modifier.clickable { onCheckedChange(!checked) } else Modifier)
            .padding(2.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            Modifier
                .padding(start = (20.dp.value * progress).dp)
                .size(26.dp)
                .clip(CircleShape)
                .background(knob),
        )
    }
}

/** A pill used for date dividers and small inline status. */
@Composable
fun Pill(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MillyType.Meta.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.Medium),
        color = theme.textSecondary,
        modifier = modifier
            .clip(CircleShape)
            .background(if (theme.isDark) theme.bubbleIncoming else theme.field)
            .padding(horizontal = Space.md, vertical = Space.xs),
    )
}

/** Unread count. Only ever drawn in the accent, and only when non-zero. */
@Composable
fun UnreadBadge(count: Int) {
    if (count <= 0) return
    Box(
        modifier = Modifier
            .defaultMinSize(minWidth = 21.dp, minHeight = 21.dp)
            .clip(CircleShape)
            .background(theme.accent)
            .padding(horizontal = 6.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = if (count > 99) "99+" else count.toString(),
            style = MillyType.Timestamp.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold),
            color = theme.onAccent,
        )
    }
}

/** Vertical breathing room, named so screens read as rhythm rather than numbers. */
@Composable
fun VGap(height: Dp) = Spacer(Modifier.height(height))

@Composable
fun ColumnScopeGap(height: Dp) = Spacer(Modifier.height(height))

/** A row of content laid out with the standard gutter. */
@Composable
fun Gutter(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = Space.gutter),
        verticalArrangement = Arrangement.spacedBy(Space.sm),
    ) { content() }
}
