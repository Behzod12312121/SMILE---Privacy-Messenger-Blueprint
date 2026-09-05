package uz.millygram.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * The delivery tick, drawn rather than composed from two icon glyphs.
 *
 * Two overlapping Material check icons read as a smudge at 15dp; a single path
 * with a controlled overlap stays legible at the size this actually appears.
 * It is a small thing, and small things at small sizes are most of what makes
 * an interface look drawn rather than assembled.
 */
@Composable
fun DeliveryTick(
    color: Color,
    modifier: Modifier = Modifier,
    size: Dp = 15.dp,
) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.14f, cap = StrokeCap.Round, join = StrokeJoin.Round)

        fun tick(shiftX: Float) {
            val path = androidx.compose.ui.graphics.Path().apply {
                moveTo(w * (0.06f + shiftX), h * 0.54f)
                lineTo(w * (0.28f + shiftX), h * 0.76f)
                lineTo(w * (0.66f + shiftX), h * 0.24f)
            }
            drawPath(path, color, style = stroke)
        }

        tick(0.15f)
    }
}

/**
 * A cross, for a message the relay never accepted.
 */
@Composable
fun FailedMark(color: Color, modifier: Modifier = Modifier, size: Dp = 15.dp) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.14f, cap = StrokeCap.Round, join = StrokeJoin.Round)
        val inset = w * 0.28f
        drawLine(color, Offset(inset, inset), Offset(w - inset, h - inset), stroke.width, StrokeCap.Round)
        drawLine(color, Offset(w - inset, inset), Offset(inset, h - inset), stroke.width, StrokeCap.Round)
    }
}

/** A small lock, used beside the encryption state in a conversation header. */
@Composable
fun LockGlyph(color: Color, modifier: Modifier = Modifier, size: Dp = 12.dp) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.16f, cap = StrokeCap.Round, join = StrokeJoin.Round)

        drawRoundRect(
            color = color,
            topLeft = Offset(w * 0.18f, h * 0.44f),
            size = androidx.compose.ui.geometry.Size(w * 0.64f, h * 0.44f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(w * 0.12f),
            style = stroke,
        )

        val shackle = androidx.compose.ui.graphics.Path().apply {
            moveTo(w * 0.32f, h * 0.44f)
            lineTo(w * 0.32f, h * 0.29f)
            cubicTo(w * 0.32f, h * 0.08f, w * 0.68f, h * 0.08f, w * 0.68f, h * 0.29f)
            lineTo(w * 0.68f, h * 0.44f)
        }
        drawPath(shackle, color, style = stroke)
    }
}
