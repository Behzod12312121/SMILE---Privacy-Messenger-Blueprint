package uz.millygram.app.theme

import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.googlefonts.Font
import androidx.compose.ui.text.googlefonts.GoogleFont
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import uz.millygram.app.R

private val provider = GoogleFont.Provider(
    providerAuthority = "com.google.android.gms.fonts",
    providerPackage = "com.google.android.gms",
    certificates = R.array.com_google_android_gms_fonts_certs,
)

/**
 * Golos Text draws Latin and Cyrillic as one design rather than bolting a
 * Cyrillic range onto a Latin face. That matters here more than usual: users
 * switch between Uzbek Latin, Uzbek Cyrillic and Russian mid-conversation, and
 * a mismatched Cyrillic range makes the two halves of a sentence look like
 * different apps.
 *
 * It also renders the two Uzbek modifier letters correctly — U+02BB in oʻ / gʻ
 * and U+02BC in aʼzo — which most default stacks flatten into a straight
 * quote.
 */
private val golos = GoogleFont("Golos Text")

val GolosText = FontFamily(
    Font(googleFont = golos, fontProvider = provider, weight = FontWeight.Normal),
    Font(googleFont = golos, fontProvider = provider, weight = FontWeight.Medium),
    Font(googleFont = golos, fontProvider = provider, weight = FontWeight.SemiBold),
    Font(googleFont = golos, fontProvider = provider, weight = FontWeight.Bold),
)

/** Monospace is reserved for material a person reads character by character. */
private val mono = GoogleFont("IBM Plex Mono")

val PlexMono = FontFamily(
    Font(googleFont = mono, fontProvider = provider, weight = FontWeight.Normal),
    Font(googleFont = mono, fontProvider = provider, weight = FontWeight.Medium),
)

/**
 * A deliberately short type scale. Telegram runs a dense, information-maximal
 * ramp; this one is larger and calmer, which reads as more expensive and is
 * easier on a cheap panel in daylight.
 */
@Suppress("unused")
object MillyType {
    val LargeTitle = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.Bold,
        fontSize = 30.sp,
        lineHeight = 35.sp,
        letterSpacing = (-0.022).em,
    )

    val Title = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
        lineHeight = 23.sp,
        letterSpacing = (-0.015).em,
    )

    val Name = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 21.sp,
        letterSpacing = (-0.012).em,
    )

    val Body = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.Normal,
        fontSize = 15.5.sp,
        lineHeight = 22.sp,
    )

    val Preview = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 20.sp,
    )

    val Label = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 21.sp,
        letterSpacing = (-0.01).em,
    )

    val Meta = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 17.sp,
    )

    val Timestamp = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.Normal,
        fontSize = 11.5.sp,
        lineHeight = 15.sp,
    )

    val SectionHeader = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.SemiBold,
        fontSize = 12.5.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.06.em,
    )

    val Notice = TextStyle(
        fontFamily = GolosText,
        fontWeight = FontWeight.Normal,
        fontSize = 12.5.sp,
        lineHeight = 18.5.sp,
        textAlign = TextAlign.Start,
    )

    /** Safety numbers and key fingerprints — grouped, spaced, unmistakable. */
    val Fingerprint = TextStyle(
        fontFamily = PlexMono,
        fontWeight = FontWeight.Medium,
        fontSize = 19.sp,
        lineHeight = 30.sp,
        letterSpacing = 0.08.em,
    )

    val MonoSmall = TextStyle(
        fontFamily = PlexMono,
        fontWeight = FontWeight.Normal,
        fontSize = 13.5.sp,
        lineHeight = 18.sp,
    )
}
