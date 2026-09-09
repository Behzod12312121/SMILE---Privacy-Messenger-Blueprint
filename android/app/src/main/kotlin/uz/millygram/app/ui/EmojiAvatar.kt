package uz.millygram.app.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.graphics.drawable.AnimatedImageDrawable
import android.os.Build
import android.util.LruCache
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import android.widget.ImageView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Avatars that are emoji, and that move.
 *
 * The assets are Microsoft's Fluent animated emoji (MIT), converted at build
 * time from the APNG they ship to animated WebP. WebP because Android decodes
 * it natively through [AnimatedImageDrawable]; APNG would need a third-party
 * decoder, and an image decoder is precisely what this app's avatars were
 * designed to avoid carrying.
 *
 * WHY THIS DOES NOT REOPEN THE HOLE THAT AVATARS WERE CLOSED FOR.
 *
 * `MillyColors` explains that avatars are generated rather than stored because
 * "a profile photo is an image decoder, and image decoders are where zero-click
 * exploits live". That reasoning is about images an *attacker* supplies. These
 * bytes ship inside the APK and are covered by its signature; which emoji shows
 * for a contact is a local choice, stored locally, and never sent or received.
 * There is no path by which anybody but the person holding the phone can decide
 * what this decoder is handed. The property that mattered is intact.
 *
 * HOW MUCH IT IS ALLOWED TO MOVE.
 *
 * A chat list holds twenty of these. Twenty animated decoders running at once
 * is dropped frames and a warm phone, and this file is next door to the avatar
 * cache whose comment ends "that is an ANR, and it was". So motion is rationed:
 *
 *   Idle  — one decoded frame, moved by Compose. A slow breath, no decoder.
 *   Tap   — the real animation, played once, then back to the still frame.
 *   Loop  — the real animation, continuously. One at a time, for the header.
 *
 * The still frame is the animation's own first frame, so nothing has to ship
 * twice and the two can never drift apart.
 */
object EmojiAvatars {

    /** What a contact shows before anybody has chosen anything for them. */
    const val DEFAULT = "grinning_face"

    fun assetPath(id: String): String = "emoji/$id.webp"

    /**
     * Everything in the pack, in the order the picker shows it.
     *
     * Read from the asset directory rather than hardcoded, so adding an emoji
     * to the build script is the only step — a list here would be a second
     * place to forget.
     */
    fun catalogue(context: Context): List<String> =
        runCatching {
            context.assets.list("emoji")
                .orEmpty()
                .filter { it.endsWith(".webp") }
                .map { it.removeSuffix(".webp") }
                .sorted()
        }.getOrDefault(emptyList())

    /**
     * Still frames, keyed by emoji and pixel size.
     *
     * Sized in bytes rather than entries because a header avatar is nine times
     * the area of a list one, and counting entries would let a few large ones
     * quietly hold far more than intended.
     */
    private val stills = object : LruCache<String, Bitmap>(6 * 1024 * 1024) {
        override fun sizeOf(key: String, value: Bitmap): Int = value.byteCount
    }

    fun still(context: Context, id: String, px: Int): Bitmap? {
        val key = "$id@$px"
        stills.get(key)?.let { return it }
        val decoded = runCatching {
            context.assets.open(assetPath(id)).use { stream ->
                // The first frame of an animated WebP is what a plain decode
                // returns, on every version this app runs on.
                BitmapFactory.decodeStream(stream)?.let { full ->
                    if (full.width == px) full
                    else Bitmap.createScaledBitmap(full, px, px, true).also {
                        if (it !== full) full.recycle()
                    }
                }
            }
        }.getOrNull() ?: return null
        stills.put(key, decoded)
        return decoded
    }
}

/** How much an emoji avatar is allowed to move. */
enum class EmojiMotion { Idle, Loop }

@Composable
fun EmojiAvatar(
    emojiId: String,
    size: Dp,
    modifier: Modifier = Modifier,
    motion: EmojiMotion = EmojiMotion.Idle,
    /** Tap plays the animation once. Null makes the avatar inert. */
    tappable: Boolean = true,
) {
    val context = LocalContext.current
    val px = with(LocalDensity.current) { size.roundToPx() }.coerceAtLeast(1)

    // Decoded off the main thread: a list scrolled onto ten new contacts would
    // otherwise decode all ten before it could draw a frame.
    val still by produceState<ImageBitmap?>(initialValue = null, emojiId, px) {
        value = withContext(Dispatchers.Default) {
            EmojiAvatars.still(context, emojiId, px)?.asImageBitmap()
        }
    }

    var playing by remember(emojiId) { mutableStateOf(false) }

    // A slow breath. Two cycles that do not share a period, so the motion never
    // settles into an obvious loop the eye can lock onto.
    val transition = rememberInfiniteTransition(label = "emoji")
    val breath by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2f * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable(tween(4200, easing = LinearEasing)),
        label = "breath",
    )
    val sway by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2f * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable(tween(6700, easing = LinearEasing)),
        label = "sway",
    )
    val float by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2f * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable(tween(5300, easing = LinearEasing)),
        label = "float",
    )

    val interaction = remember { MutableInteractionSource() }
    val tapModifier =
        if (tappable && motion == EmojiMotion.Idle) {
            Modifier.clickable(interaction, indication = null) { playing = true }
        } else {
            Modifier
        }

    // No clip, no ground, no disc.
    //
    // The emoji is the avatar, not something placed inside one. A circle behind
    // it would put a border on artwork that was rendered with its own edge
    // lighting and its own shadow, and the two never agree — the disc reads as a
    // sticker the emoji has been stuck onto. Nothing is drawn here but the
    // emoji, so what the eye gets is the object, floating.
    Box(
        modifier = modifier.size(size).then(tapModifier),
        contentAlignment = Alignment.Center,
    ) {
        val animate = motion == EmojiMotion.Loop || playing
        if (animate && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            AnimatedEmoji(
                emojiId = emojiId,
                size = size,
                loop = motion == EmojiMotion.Loop,
                onFinished = { playing = false },
            )
        } else {
            val ready = still
            if (ready == null) {
                // Nothing, deliberately. A placeholder disc would be the one
                // frame where the border this mark is meant to avoid appears.
                Box(Modifier.size(size))
            } else {
                Canvas(Modifier.size(size)) {
                    // Three cycles, none of them sharing a period, so the loop
                    // never lands on itself and the eye cannot catch the seam.
                    // This is the whole of "alive" at rest: a breath, a lean,
                    // and a float, all small enough to read as life rather than
                    // as animation.
                    val scale = 1f + 0.034f * kotlin.math.sin(breath)
                    val tilt = 2.6f * kotlin.math.sin(sway)
                    val bob = size.toPx() * 0.022f * kotlin.math.sin(float)
                    withTransform({
                        translate(top = bob)
                        rotate(tilt)
                        scale(scale, scale)
                    }) {
                        drawImage(ready)
                    }
                }
            }
        }
    }
}

/**
 * The real animation, through the platform decoder.
 *
 * An [ImageView] rather than a Compose painter because [AnimatedImageDrawable]
 * is a framework drawable with its own timing, and handing it to a View that
 * already knows how to host one is less machinery than driving frames by hand —
 * and far less than a second decoder would be.
 */
@Composable
private fun AnimatedEmoji(
    emojiId: String,
    size: Dp,
    loop: Boolean,
    onFinished: () -> Unit,
) {
    val context = LocalContext.current
    val drawable = remember(emojiId, loop) {
        runCatching {
            val source = ImageDecoder.createSource(context.assets, EmojiAvatars.assetPath(emojiId))
            (ImageDecoder.decodeDrawable(source) as? AnimatedImageDrawable)?.apply {
                repeatCount = if (loop) AnimatedImageDrawable.REPEAT_INFINITE else 0
            }
        }.getOrNull()
    }

    // A single pass has to hand control back, or the avatar would sit on its
    // last frame for good. The drawable does not report completion on every
    // version, so the duration is taken from the asset and used as the timer.
    if (!loop) {
        LaunchedEffect(emojiId, drawable) {
            kotlinx.coroutines.delay(EMOJI_PLAY_MS)
            onFinished()
        }
    }

    if (drawable == null) {
        onFinished()
        return
    }

    AndroidView(
        factory = { ctx ->
            ImageView(ctx).apply {
                scaleType = ImageView.ScaleType.FIT_CENTER
                setImageDrawable(drawable)
                drawable.start()
            }
        },
        modifier = Modifier.size(size),
        onRelease = { drawable.stop() },
    )
}

/**
 * How long one pass is given before the avatar returns to its still frame.
 *
 * The pack is built to a three second timeline, and a little margin is cheaper
 * than cutting the last frames off an animation that ran slightly long.
 */
private const val EMOJI_PLAY_MS = 3_200L
