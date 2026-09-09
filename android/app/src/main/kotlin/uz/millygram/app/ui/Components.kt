package uz.millygram.app.ui

import androidx.compose.animation.core.animateFloat
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
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.runtime.remember
import androidx.compose.runtime.produceState
import androidx.compose.ui.graphics.ImageBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
 * A generated avatar.
 *
 * There are no profile photos anywhere in this app, and that is a security
 * decision rather than an aesthetic one: a photo means an image decoder, and
 * image decoders are where the zero-click exploits in every other messenger
 * have lived.
 *
 * The art comes from a seed the gateway assigns at registration and serves with
 * an account's keys. Nothing a peer sends can influence it — there is no field
 * to send — so this is an identifier the person behind it cannot dress up.
 *
 * A null seed means an account whose keys have not been fetched yet. That falls
 * back to initials rather than to an empty circle, because a list of blank
 * discs is worse than a list of letters.
 */
@Composable
fun Avatar(
    seed: ByteArray?,
    name: String,
    size: Dp,
    modifier: Modifier = Modifier,
    /** Slow drift, for the one avatar on screen at a time that is worth it. */
    animated: Boolean = false,
    /**
     * The emoji this device shows for the contact, if one has been chosen.
     *
     * Takes precedence over the generated cloud, because it is a deliberate
     * choice by the person looking at the screen and the cloud is a default.
     * Null falls through to the cloud, so nothing changes for a contact nobody
     * has customised.
     */
    emojiId: String? = null,
) {
    if (emojiId != null) {
        EmojiAvatar(
            emojiId = emojiId,
            size = size,
            modifier = modifier,
            // Only the one avatar a screen is built around gets a running
            // decoder. Everything in a list breathes on a single frame.
            motion = if (animated) EmojiMotion.Loop else EmojiMotion.Idle,
        )
        return
    }
    if (seed == null || seed.isEmpty()) {
        InitialsAvatar(name, size, modifier)
        return
    }

    val density = LocalDensity.current
    val px = with(density) { size.roundToPx() }.coerceAtLeast(1)

    // Keyed on the seed's *contents*, not the array. ByteArray equality is
    // identity, and the seed is decoded fresh on every read, so keying on the
    // array itself made every recomposition a cache miss — which meant redoing
    // the whole render, on the main thread, several times a second. That is an
    // ANR, and it was.
    val seedKey = remember(seed) { seed.contentHashCode() }

    // Generated off the main thread even so. The first render of a given seed
    // is real work — blurred strokes on a software canvas — and a chat list
    // scrolled onto ten new contacts at once would do all ten before it could
    // draw a frame.
    val image by produceState<ImageBitmap?>(initialValue = null, seedKey, px) {
        value = withContext(Dispatchers.Default) {
            NeuralCloud.bitmap(seed, px).asImageBitmap()
        }
    }

    // The bitmap is generated once; motion comes from moving it. Regenerating
    // per frame would cost more than the rest of the list combined, and this is
    // indistinguishable at the sizes it runs at.
    val drift = if (animated) {
        val transition = rememberInfiniteTransition(label = "avatar")
        val spin by transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable<Float>(tween(48_000, easing = LinearEasing)),
            label = "spin",
        )
        spin
    } else {
        0f
    }

    val ready = image
    if (ready == null) {
        // The ground the art is drawn on, so the row does not flash a light
        // disc for one frame before the cloud arrives.
        Box(modifier.size(size).clip(CircleShape).background(Color(0xFF05070C)))
        return
    }

    Box(
        modifier = modifier.size(size).clip(CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.foundation.Canvas(Modifier.size(size)) {
            val scale = if (animated) 1.06f + 0.03f * kotlin.math.sin(drift * 0.0349f) else 1f
            withTransform({
                rotate(drift)
                scale(scale, scale)
            }) {
                drawImage(ready)
            }
        }
    }
}

@Composable
private fun InitialsAvatar(name: String, size: Dp, modifier: Modifier) {
    val fontSize = (size.value * 0.34f).sp
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(avatarColorFor(name)),
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
    // Clamped for the colour because lerp does not clamp, and a spring that
    // overshoots 1 would push the track past the accent into an out-of-gamut
    // colour on the way in.
    val track = androidx.compose.ui.graphics.lerp(
        if (theme.isDark) Color(0xFF2A3338) else Color(0xFFDDE2E4),
        theme.accent,
        progress.coerceIn(0f, 1f),
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
                // offset, not padding. This spring is underdamped on purpose,
                // so progress overshoots both ends — and padding throws on a
                // negative value. Turning the switch off sent it below zero and
                // took the whole app down with it every time. offset accepts
                // negative values, so the overshoot now does what it was always
                // meant to do: let the knob run a hair past the end and settle.
                .offset(x = (20f * progress).dp)
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
