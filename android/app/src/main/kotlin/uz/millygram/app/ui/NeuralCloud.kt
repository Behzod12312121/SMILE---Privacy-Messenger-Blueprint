package uz.millygram.app.ui

import android.graphics.Bitmap
import android.graphics.BlurMaskFilter
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.Shader
import android.util.LruCache
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/**
 * The avatar art: volumetric filaments lit from inside.
 *
 * Drawn rather than downloaded. There is no profile photo anywhere in this app
 * and there is no route that would accept one, so an avatar can never be a
 * channel for one user to push chosen bytes at another — the surface that has
 * produced the zero-click exploits in every other messenger.
 *
 * Everything here comes from the eight bytes the gateway assigns at
 * registration. The account holder does not choose them and cannot change
 * them, which is what makes an avatar an identifier rather than a costume.
 *
 * Deliberately Canvas and not a runtime shader. AGSL would be a closer match to
 * the reference, and it needs API 33 — on a market where most handsets are
 * older than that, half the users would see a different app. Overlapping soft
 * gradients and blurred strokes get most of the way there on every device this
 * app supports.
 */
object NeuralCloud {

    /**
     * Palettes, not free hue rotation.
     *
     * A hue picked at random lands in olive and mustard as often as anywhere
     * good, and one user in eight would be stuck with it forever. These are
     * chosen so every account gets something worth having.
     */
    private val RAMPS = arrayOf(
        intArrayOf(0xFFFF3DA8.toInt(), 0xFF37E8FF.toInt()),
        intArrayOf(0xFF7C5CFF.toInt(), 0xFF34E7D6.toInt()),
        intArrayOf(0xFF3DA5FF.toInt(), 0xFFA855F7.toInt()),
        intArrayOf(0xFF2BE8A0.toInt(), 0xFF3D9CFF.toInt()),
        intArrayOf(0xFFFF4D6D.toInt(), 0xFFC77DFF.toInt()),
        intArrayOf(0xFF00E5FF.toInt(), 0xFF5B6BFF.toInt()),
        intArrayOf(0xFF45BBD4.toInt(), 0xFFE3A857.toInt()),
        intArrayOf(0xFFFF7A3D.toInt(), 0xFFFFD93D.toInt()),
    )

    /**
     * Bitmaps are cached because a chat list asks for the same handful of
     * avatars on every frame it scrolls, and regenerating one per frame would
     * be the single most expensive thing the list does. Four megabytes holds
     * roughly a hundred list-sized avatars.
     */
    private val cache = object : LruCache<String, Bitmap>(4 * 1024 * 1024) {
        override fun sizeOf(key: String, value: Bitmap): Int = value.byteCount
    }

    fun bitmap(seed: ByteArray, sizePx: Int): Bitmap {
        val key = seed.joinToString("") { "%02x".format(it) } + "@" + sizePx
        cache.get(key)?.let { return it }
        val made = render(seed, sizePx)
        cache.put(key, made)
        return made
    }

    /** Deterministic stream of numbers in 0..1 from the seed. xorshift32. */
    private class Rand(seed: ByteArray) {
        private var s: Int = run {
            var h = -0x7ee3623b // FNV offset basis
            for (b in seed) {
                h = h xor (b.toInt() and 0xFF)
                h *= 0x01000193
            }
            if (h == 0) 0x2545F491 else h
        }

        fun next(): Float {
            s = s xor (s shl 13)
            s = s xor (s ushr 17)
            s = s xor (s shl 5)
            return ((s.toLong() and 0xFFFFFFFFL).toFloat() / 4294967296f)
        }

        fun range(lo: Float, hi: Float): Float = lo + next() * (hi - lo)
        fun int(bound: Int): Int = (next() * bound).toInt().coerceIn(0, bound - 1)
    }

    private fun render(seed: ByteArray, sizePx: Int): Bitmap {
        val bmp = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        val c = Canvas(bmp)
        val r = Rand(seed)
        val n = sizePx.toFloat()
        val cx = n / 2f
        val cy = n / 2f
        val rad = n / 2f

        val ramp = RAMPS[r.int(RAMPS.size)]
        val hot = ramp[0]
        val cool = ramp[1]

        // Everything is drawn inside the disc. Clipping once here means no
        // individual glow has to worry about spilling past the edge.
        c.save()
        val disc = Path().apply { addCircle(cx, cy, rad, Path.Direction.CW) }
        c.clipPath(disc)

        // A near-black ground, lifted very slightly where the cloud sits. The
        // disc stays opaque so it reads as an avatar on the light theme too,
        // where a transparent glow would dissolve into the background.
        val ground = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = RadialGradient(
                cx * 0.85f, cy * 0.8f, rad * 1.35f,
                0xFF141A2E.toInt(), 0xFF05070C.toInt(), Shader.TileMode.CLAMP,
            )
        }
        c.drawCircle(cx, cy, rad, ground)

        // Volumetric haze: a few wide, soft blobs stacked additively. This is
        // what gives depth — the filaments alone read as flat wire.
        val haze = Paint(Paint.ANTI_ALIAS_FLAG)
        for (i in 0 until 7) {
            val a = r.range(0f, 6.2832f)
            val d = rad * r.range(0.08f, 0.52f)
            val bx = cx + cos(a) * d
            val by = cy + sin(a) * d
            val br = rad * r.range(0.62f, 1.25f)
            val tint = if (i % 2 == 0) hot else cool
            haze.shader = RadialGradient(
                bx, by, br,
                intArrayOf(withAlpha(tint, 205), withAlpha(tint, 78), withAlpha(tint, 0)),
                floatArrayOf(0f, 0.42f, 1f), Shader.TileMode.CLAMP,
            )
            c.drawCircle(bx, by, br, haze)
        }

        val wash = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = RadialGradient(
                cx, cy, rad,
                intArrayOf(withAlpha(blend(hot, cool, 0.5f), 96), withAlpha(cool, 46), withAlpha(cool, 0)),
                floatArrayOf(0f, 0.6f, 1f), Shader.TileMode.CLAMP,
            )
        }
        c.drawCircle(cx, cy, rad, wash)

        // Filaments. Each is a curve wandering across the disc, stroked twice:
        // once wide and blurred for the bloom, once thin and bright for the
        // core. That pairing is what makes a line look like it is emitting
        // light rather than being painted in a light colour.
        val strands = 7 + r.int(5)
        for (i in 0 until strands) {
            val path = Path()
            val a0 = r.range(0f, 6.2832f)
            val start = rad * r.range(0.15f, 0.95f)
            var px = cx + cos(a0) * start
            var py = cy + sin(a0) * start
            path.moveTo(px, py)

            val hops = 2 + r.int(3)
            for (h in 0 until hops) {
                val a1 = a0 + r.range(-2.4f, 2.4f)
                val len = rad * r.range(0.3f, 0.85f)
                val nx = (cx + cos(a1) * rad * r.range(-0.9f, 0.9f))
                val ny = (cy + sin(a1) * rad * r.range(-0.9f, 0.9f))
                val mx = (px + nx) / 2f + r.range(-len, len) * 0.4f
                val my = (py + ny) / 2f + r.range(-len, len) * 0.4f
                path.quadTo(mx, my, nx, ny)
                px = nx
                py = ny
            }

            val tint = if (i % 2 == 0) hot else cool
            val bloom = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                style = Paint.Style.STROKE
                strokeCap = Paint.Cap.ROUND
                strokeJoin = Paint.Join.ROUND
                strokeWidth = n * r.range(0.055f, 0.105f)
                color = withAlpha(tint, 150)
                maskFilter = BlurMaskFilter(n * 0.085f, BlurMaskFilter.Blur.NORMAL)
            }
            c.drawPath(path, bloom)

            val core = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                style = Paint.Style.STROKE
                strokeCap = Paint.Cap.ROUND
                strokeJoin = Paint.Join.ROUND
                strokeWidth = n * r.range(0.010f, 0.020f)
                color = withAlpha(blend(tint, Color.WHITE, 0.5f), 235)
                maskFilter = BlurMaskFilter(n * 0.012f, BlurMaskFilter.Blur.NORMAL)
            }
            c.drawPath(path, core)

            // A brighter node where the strand ends, like a synapse firing.
            val node = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = withAlpha(blend(tint, Color.WHITE, 0.6f), 235)
                maskFilter = BlurMaskFilter(n * 0.03f, BlurMaskFilter.Blur.NORMAL)
            }
            c.drawCircle(px, py, n * r.range(0.012f, 0.026f), node)
        }

        // Dust. Small, sparse and never near the rim, where it would read as
        // dirt on the edge rather than as depth.
        val dust = Paint(Paint.ANTI_ALIAS_FLAG)
        val motes = 14 + r.int(14)
        for (i in 0 until motes) {
            val a = r.range(0f, 6.2832f)
            val d = rad * r.range(0f, 0.82f)
            val alpha = (r.range(0.25f, 1f) * 210).toInt()
            dust.color = withAlpha(if (i % 3 == 0) hot else Color.WHITE, alpha)
            c.drawCircle(cx + cos(a) * d, cy + sin(a) * d, n * r.range(0.004f, 0.011f), dust)
        }

        // The core, last, so it sits on top of everything and gives the eye a
        // centre to land on at 52dp where the structure is illegible.
        val core = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = RadialGradient(
                cx, cy, rad * 0.55f,
                intArrayOf(withAlpha(Color.WHITE, 200), withAlpha(hot, 130), withAlpha(hot, 0)),
                floatArrayOf(0f, 0.32f, 1f), Shader.TileMode.CLAMP,
            )
        }
        c.drawCircle(cx, cy, rad * 0.55f, core)

        // A dark vignette at the rim keeps the disc from glowing into the row
        // separator beside it.
        val vignette = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = RadialGradient(
                cx, cy, rad,
                intArrayOf(withAlpha(Color.BLACK, 0), withAlpha(Color.BLACK, 0), withAlpha(Color.BLACK, 130)),
                floatArrayOf(0f, 0.72f, 1f), Shader.TileMode.CLAMP,
            )
        }
        c.drawCircle(cx, cy, rad, vignette)

        c.restore()
        return bmp
    }

    private fun withAlpha(color: Int, alpha: Int): Int =
        (color and 0x00FFFFFF) or ((alpha.coerceIn(0, 255)) shl 24)

    private fun blend(a: Int, b: Int, t: Float): Int {
        val u = 1f - t
        return Color.rgb(
            (Color.red(a) * u + Color.red(b) * t).toInt(),
            (Color.green(a) * u + Color.green(b) * t).toInt(),
            (Color.blue(a) * u + Color.blue(b) * t).toInt(),
        )
    }

    /** Frees the cache when the process is asked to give memory back. */
    fun trim() = cache.evictAll()
}
