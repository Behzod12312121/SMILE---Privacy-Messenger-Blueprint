package uz.millygram.app.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.theme
import kotlin.math.sin

/**
 * The light that runs around something new.
 *
 * A conversation with an unread message does not get a blue pill with a number
 * in it. It gets a border of moving colour — four strokes of the same rotating
 * sweep gradient, each a little wider, fainter and further behind the last, and
 * each turning at a slightly different rate. That difference is the whole
 * trick: strokes that rotate together read as a spinning ring, and strokes that
 * drift apart read as liquid.
 *
 * The count is gone deliberately. Knowing there are four unread messages rather
 * than three changes nothing anybody does, and the number was the most
 * recognisably borrowed thing on the screen.
 */

/** Loops back to its first colour, so the sweep has no seam. */
private val RAMP = listOf(
    Color(0xFF45BBD4),
    Color(0xFF6E8BFF),
    Color(0xFFB07CF3),
    Color(0xFFF58ED8),
    Color(0xFF5FD3C4),
    Color(0xFF45BBD4),
)

private fun sample(t: Float): Color {
    val p = ((t % 1f) + 1f) % 1f
    val span = RAMP.size - 1
    val scaled = p * span
    val i = scaled.toInt().coerceIn(0, span - 1)
    return lerp(RAMP[i], RAMP[i + 1], scaled - i)
}

/**
 * A sweep gradient rotated by [phase].
 *
 * Compose's sweep gradient has no rotation, so the ramp is resampled at fixed
 * stops with the phase added instead. Same result, and it stays seamless
 * because the ramp ends where it starts.
 */
private fun rotating(phase: Float, center: Offset, alpha: Float): Brush {
    val steps = 12
    val stops = Array(steps + 1) { i ->
        val t = i.toFloat() / steps
        t to sample(t + phase).copy(alpha = alpha)
    }
    return Brush.sweepGradient(colorStops = stops, center = center)
}

/**
 * Draws the moving border behind whatever this modifies.
 *
 * Only composed for rows that actually have something unread — an idle chat
 * list animates nothing, which matters on a phone somebody leaves this screen
 * open on.
 */
@Composable
fun Modifier.liquidGlow(corner: Dp = 18.dp): Modifier {
    val transition = rememberInfiniteTransition(label = "liquid")
    val spin by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable<Float>(tween(4200, easing = LinearEasing)),
        label = "spin",
    )
    // A slow swell on top of the rotation. Without it the border turns at a
    // constant rate and reads as machinery; with it the light gathers and
    // thins the way moving water does.
    val swell by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable<Float>(
            animation = tween(2600, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "swell",
    )

    val glowTint = theme.accent

    return drawBehind {
        val r = CornerRadius(corner.toPx(), corner.toPx())
        val center = Offset(size.width / 2f, size.height / 2f)

        // A faint wash inside, so the row still reads as unread in the moment
        // the bright part of the border is on the far side of it.
        drawRoundRect(
            brush = Brush.horizontalGradient(
                listOf(
                    glowTint.copy(alpha = 0.10f),
                    Color(0xFFB07CF3).copy(alpha = 0.07f),
                    glowTint.copy(alpha = 0.10f),
                ),
            ),
            cornerRadius = r,
        )

        // Widest and faintest first. Layered rather than blurred: a real blur
        // needs RenderEffect on API 31 and this app supports 26, and four
        // stacked strokes with falling alpha give the same soft edge on every
        // device.
        val layers = listOf(
            18.dp to 0.10f,
            11.dp to 0.17f,
            5.5.dp to 0.30f,
            2.dp to 0.85f,
        )
        layers.forEachIndexed { index, (width, alpha) ->
            val drift = index * 0.055f
            val wobble = sin((swell + drift) * 6.2832f) * 0.035f
            val inset = width.toPx() / 2f
            drawRoundRect(
                brush = rotating(spin + drift + wobble, center, alpha),
                topLeft = Offset(inset, inset),
                size = Size(size.width - inset * 2f, size.height - inset * 2f),
                cornerRadius = CornerRadius(
                    (corner.toPx() - inset).coerceAtLeast(0f),
                    (corner.toPx() - inset).coerceAtLeast(0f),
                ),
                style = Stroke(width = width.toPx()),
            )
        }
    }
}
