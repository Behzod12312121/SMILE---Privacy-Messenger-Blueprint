package uz.millygram.app.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.text.selection.LocalTextSelectionColors
import androidx.compose.foundation.text.selection.TextSelectionColors
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat

val LocalMillyColors = staticCompositionLocalOf { LightColors }

/**
 * Spacing is a small fixed set rather than free-form numbers, so screens stay
 * in rhythm with each other. The values are larger than a typical messenger's:
 * density is where Telegram lives, and matching it would make this look like a
 * reskin of it.
 */
object Space {
    val hairline = 1.dp
    val xs = 4.dp
    val sm = 8.dp
    val md = 12.dp
    val lg = 16.dp
    val xl = 20.dp
    val xxl = 28.dp

    /** Screen gutter. Wide enough that text never crowds the bezel. */
    val gutter = 20.dp

    /** Below this, a control is hard to hit reliably one-handed on a bus. */
    val minTouchTarget = 48.dp
}

object Radius {
    val field = 12.dp
    val card = 16.dp
    val bubble = 18.dp

    /** The corner nearest the speaker, tightened so direction reads without a tail. */
    val bubbleAnchor = 6.dp
}

@Composable
fun MillyGramTheme(
    dark: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (dark) DarkColors else LightColors
    val view = LocalView.current

    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = Color.Transparent.toArgb()
            window.navigationBarColor = Color.Transparent.toArgb()
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
        }
    }

    // Material3 is present for its components, but the palette above is the
    // source of truth; the scheme here only keeps stray Material defaults from
    // introducing a colour the design never chose.
    val scheme = if (dark) {
        darkColorScheme(
            primary = colors.accent,
            onPrimary = colors.onAccent,
            background = colors.background,
            onBackground = colors.textPrimary,
            surface = colors.surfaceRaised,
            onSurface = colors.textPrimary,
        )
    } else {
        lightColorScheme(
            primary = colors.accent,
            onPrimary = colors.onAccent,
            background = colors.background,
            onBackground = colors.textPrimary,
            surface = colors.surfaceRaised,
            onSurface = colors.textPrimary,
        )
    }

    CompositionLocalProvider(
        LocalMillyColors provides colors,
        LocalTextSelectionColors provides TextSelectionColors(
            handleColor = colors.accent,
            backgroundColor = colors.accent.copy(alpha = 0.24f),
        ),
    ) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

/** Shorthand so screens read `theme.textSecondary` rather than a local lookup. */
val theme: MillyColors
    @Composable get() = LocalMillyColors.current

/** Text that defaults to the palette instead of Material's onBackground. */
@Composable
fun MillyText(
    text: String,
    style: TextStyle,
    color: Color = LocalMillyColors.current.textPrimary,
    maxLines: Int = Int.MAX_VALUE,
    overflow: androidx.compose.ui.text.style.TextOverflow = androidx.compose.ui.text.style.TextOverflow.Clip,
    modifier: androidx.compose.ui.Modifier = androidx.compose.ui.Modifier,
) {
    Text(
        text = text,
        style = style,
        color = color,
        maxLines = maxLines,
        overflow = overflow,
        modifier = modifier,
    )
}
