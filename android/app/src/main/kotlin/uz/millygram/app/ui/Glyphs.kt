package uz.millygram.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * A shield with a check inside, drawn rather than imported.
 *
 * The stock Material shield is heavier than everything else on these screens
 * and carries a different corner language. One consistent stroke weight across
 * the few security glyphs the app uses does more for a coherent feel than any
 * amount of colour work.
 */
@Composable
fun ShieldGlyph(color: Color, modifier: Modifier = Modifier, size: Dp = 20.dp) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.09f, cap = StrokeCap.Round, join = StrokeJoin.Round)

        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.13f)
            lineTo(w * 0.20f, h * 0.25f)
            lineTo(w * 0.20f, h * 0.47f)
            cubicTo(w * 0.20f, h * 0.65f, w * 0.32f, h * 0.81f, w * 0.50f, h * 0.87f)
            cubicTo(w * 0.68f, h * 0.81f, w * 0.80f, h * 0.65f, w * 0.80f, h * 0.47f)
            lineTo(w * 0.80f, h * 0.25f)
            close()
        }
        drawPath(shield, color, style = stroke)

        val check = Path().apply {
            moveTo(w * 0.39f, h * 0.50f)
            lineTo(w * 0.47f, h * 0.59f)
            lineTo(w * 0.62f, h * 0.42f)
        }
        drawPath(check, color, style = stroke)
    }
}

/** A key, used beside the safety-number row. */
@Composable
fun KeyGlyph(color: Color, modifier: Modifier = Modifier, size: Dp = 20.dp) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.09f, cap = StrokeCap.Round, join = StrokeJoin.Round)

        drawCircle(
            color = color,
            radius = w * 0.19f,
            center = androidx.compose.ui.geometry.Offset(w * 0.34f, h * 0.66f),
            style = stroke,
        )
        val shaft = Path().apply {
            moveTo(w * 0.47f, h * 0.53f)
            lineTo(w * 0.82f, h * 0.18f)
            moveTo(w * 0.68f, h * 0.32f)
            lineTo(w * 0.79f, h * 0.43f)
        }
        drawPath(shaft, color, style = stroke)
    }
}

/** An eye with a slash, for the permanently-off presence row. */
@Composable
fun EyeOffGlyph(color: Color, modifier: Modifier = Modifier, size: Dp = 20.dp) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.09f, cap = StrokeCap.Round, join = StrokeJoin.Round)

        val eye = Path().apply {
            moveTo(w * 0.10f, h * 0.50f)
            cubicTo(w * 0.28f, h * 0.24f, w * 0.72f, h * 0.24f, w * 0.90f, h * 0.50f)
            cubicTo(w * 0.72f, h * 0.76f, w * 0.28f, h * 0.76f, w * 0.10f, h * 0.50f)
            close()
        }
        drawPath(eye, color, style = stroke)
        drawCircle(
            color = color,
            radius = w * 0.11f,
            center = androidx.compose.ui.geometry.Offset(w * 0.50f, h * 0.50f),
            style = stroke,
        )
        drawPath(
            Path().apply {
                moveTo(w * 0.16f, h * 0.16f)
                lineTo(w * 0.84f, h * 0.84f)
            },
            color,
            style = stroke,
        )
    }
}

/** A phone outline, for the active-devices row. */
@Composable
fun DeviceGlyph(color: Color, modifier: Modifier = Modifier, size: Dp = 20.dp) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.09f, cap = StrokeCap.Round, join = StrokeJoin.Round)

        drawRoundRect(
            color = color,
            topLeft = androidx.compose.ui.geometry.Offset(w * 0.28f, h * 0.12f),
            size = androidx.compose.ui.geometry.Size(w * 0.44f, h * 0.76f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(w * 0.11f),
            style = stroke,
        )
        drawPath(
            Path().apply {
                moveTo(w * 0.44f, h * 0.75f)
                lineTo(w * 0.56f, h * 0.75f)
            },
            color,
            style = stroke,
        )
    }
}

/** A bell, for the notification section. */
@Composable
fun BellGlyph(color: Color, modifier: Modifier = Modifier, size: Dp = 20.dp) {
    Canvas(modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = w * 0.09f, cap = StrokeCap.Round, join = StrokeJoin.Round)

        val body = Path().apply {
            moveTo(w * 0.22f, h * 0.66f)
            cubicTo(w * 0.22f, h * 0.30f, w * 0.34f, h * 0.20f, w * 0.50f, h * 0.20f)
            cubicTo(w * 0.66f, h * 0.20f, w * 0.78f, h * 0.30f, w * 0.78f, h * 0.66f)
            close()
        }
        drawPath(body, color, style = stroke)
        drawLine(
            color,
            androidx.compose.ui.geometry.Offset(w * 0.14f, h * 0.70f),
            androidx.compose.ui.geometry.Offset(w * 0.86f, h * 0.70f),
            stroke.width,
            StrokeCap.Round,
        )
        drawLine(
            color,
            androidx.compose.ui.geometry.Offset(w * 0.42f, h * 0.80f),
            androidx.compose.ui.geometry.Offset(w * 0.58f, h * 0.80f),
            stroke.width,
            StrokeCap.Round,
        )
    }
}
