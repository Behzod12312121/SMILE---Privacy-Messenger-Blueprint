package uz.millygram.app.theme

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

/**
 * The palette.
 *
 * The accent is a Samarkand tilework teal, chosen partly because it is rooted
 * in something local and partly because it is deliberately *not* Telegram's
 * blue — an app that copies the incumbent's colour gets read as a fork of it.
 *
 * Dark mode is true black rather than the dark grey every other messenger
 * uses. On the OLED panels most phones ship now that is a real battery saving,
 * and it makes bubbles float rather than sit in a grey box.
 *
 * The accent appears in exactly five places: unread badge, outgoing bubble,
 * send button, active control, and links. Restraint is the point — colour used
 * everywhere stops meaning anything.
 */
@Immutable
data class MillyColors(
    val background: Color,
    val surface: Color,
    val surfaceRaised: Color,
    val field: Color,
    val hairline: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textTertiary: Color,
    val textDisabled: Color,
    val accent: Color,
    val onAccent: Color,
    val accentMuted: Color,
    val bubbleIncoming: Color,
    val bubbleOutgoing: Color,
    val onBubbleIncoming: Color,
    val onBubbleOutgoing: Color,
    val noticeSurface: Color,
    val noticeText: Color,
    val noticeStrong: Color,
    val verified: Color,
    /** Failed sends, and the identity-change warning. Used sparingly. */
    val danger: Color,
    val dangerSurface: Color,
    val isDark: Boolean,
)

val LightColors = MillyColors(
    background = Color(0xFFFFFFFF),
    surface = Color(0xFFF4F6F7),
    surfaceRaised = Color(0xFFFFFFFF),
    field = Color(0xFFF1F3F4),
    hairline = Color(0xFFE7EAEB),
    textPrimary = Color(0xFF14181A),
    textSecondary = Color(0xFF5C6A70),
    textTertiary = Color(0xFF8A979D),
    textDisabled = Color(0xFFC2CBCF),
    accent = Color(0xFF0F7A8F),
    onAccent = Color(0xFFFFFFFF),
    accentMuted = Color(0xFFE9F2F4),
    bubbleIncoming = Color(0xFFFFFFFF),
    bubbleOutgoing = Color(0xFF0F7A8F),
    onBubbleIncoming = Color(0xFF14181A),
    onBubbleOutgoing = Color(0xFFFFFFFF),
    noticeSurface = Color(0xFFE9F2F4),
    noticeText = Color(0xFF3F5B62),
    noticeStrong = Color(0xFF26454D),
    verified = Color(0xFF2F8A5E),
    danger = Color(0xFFB3261E),
    dangerSurface = Color(0xFFFCEBE9),
    isDark = false,
)

val DarkColors = MillyColors(
    background = Color(0xFF000000),
    surface = Color(0xFF000000),
    surfaceRaised = Color(0xFF0E1214),
    field = Color(0xFF171C1F),
    hairline = Color(0xFF1C2225),
    textPrimary = Color(0xFFF2F5F6),
    textSecondary = Color(0xFF94A2A8),
    textTertiary = Color(0xFF6B7880),
    textDisabled = Color(0xFF4A555B),
    accent = Color(0xFF45BBD4),
    onAccent = Color(0xFF04222A),
    accentMuted = Color(0xFF0C2429),
    bubbleIncoming = Color(0xFF14191B),
    // A bright accent bubble glares at night, so the outgoing bubble drops to a
    // deep teal while the accent itself stays bright for small controls.
    bubbleOutgoing = Color(0xFF0E5361),
    onBubbleIncoming = Color(0xFFEDF1F2),
    onBubbleOutgoing = Color(0xFFEAF7FA),
    noticeSurface = Color(0xFF0C2429),
    noticeText = Color(0xFF9BC2CA),
    noticeStrong = Color(0xFFC7E5EB),
    verified = Color(0xFF4FB889),
    // Muted against black: a saturated red on an OLED ground reads as an
    // emergency, and this warning needs to be noticed, not panicked over.
    danger = Color(0xFFFF7A70),
    dangerSurface = Color(0xFF2A1416),
    isDark = true,
)

/**
 * Avatar colours. Generated from the account id rather than stored, because a
 * profile photo is an image decoder, and image decoders are where zero-click
 * exploits live. These are muted and share a lightness so no contact shouts
 * louder than another.
 */
val AvatarPalette = listOf(
    Color(0xFFB0645C),
    Color(0xFF5E9A78),
    Color(0xFF7B7FB5),
    Color(0xFFA6784F),
    Color(0xFF4E8DA6),
    Color(0xFF98618E),
    Color(0xFF5F8C86),
    Color(0xFFA66F80),
)

/** Stable across devices and restarts: same id, same colour, no storage needed. */
fun avatarColorFor(id: String): Color {
    var hash = 0
    for (character in id) hash = (hash * 31 + character.code) and 0x7fffffff
    return AvatarPalette[hash % AvatarPalette.size]
}

/**
 * Initials for a generated avatar. Takes the first letter of the first two
 * words, which keeps Uzbek names like "Gʻayrat Toʻrayev" reading as GT rather
 * than mangling the modifier letter.
 */
fun initialsFor(name: String): String {
    val words = name.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    if (words.isEmpty()) return "?"
    if (words.size == 1) return words[0].take(1).uppercase()
    return (words[0].take(1) + words[1].take(1)).uppercase()
}
