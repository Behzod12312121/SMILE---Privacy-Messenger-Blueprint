package uz.millygram.app.ui

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.border
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.LaunchedEffect
import kotlinx.coroutines.launch
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.PlatformImeOptions
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme
import uz.millygram.protocol.Protocol

/**
 * A conversation.
 *
 * Two decisions carry most of the character. First, bubbles have no tails: the
 * corner nearest the speaker is simply tightened, which reads as direction
 * without the cartoon pointer every other messenger draws. Second, the compose
 * bar holds an input and a send button and nothing else — no attachment clip,
 * no microphone, no sticker key. That bar is the clearest statement the app
 * makes about what it is.
 */
@Composable
fun ConversationScreen(
    peerAci: String,
    peerName: String,
    /** Gateway-assigned; null until this device has the peer's keys. */
    peerAvatarSeed: ByteArray?,
    /** The emoji this device shows for the peer. Local only. */
    peerAvatarEmoji: String? = null,
    timeline: List<TimelineItem>,
    onBack: () -> Unit,
    onOpenProfile: () -> Unit,
    onSend: (String) -> Unit,
    onRetry: (Long) -> Unit = {},
    identityChanged: Boolean = false,
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(theme.surface)
            .imePadding(),
    ) {
        ConversationHeader(peerAci, peerName, peerAvatarSeed, peerAvatarEmoji, onBack, onOpenProfile)

        // Shown when a message arrived from this contact signed by an identity
        // key we had not pinned. Everything below it in the thread predates a
        // key we cannot vouch for, so the warning sits above the timeline
        // rather than inside it, and does not go away on its own.
        if (identityChanged) IdentityChangedBanner(onOpenProfile)

        val listState = rememberLazyListState()
        val scope = rememberCoroutineScope()

        // "At the bottom" is deliberately generous. Requiring the very last
        // pixel means a thread that is one line short of filling the screen, or
        // a user who nudged it a few dp, stops following new messages for no
        // reason they could see.
        val atBottom by remember {
            derivedStateOf {
                val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()
                    ?: return@derivedStateOf true
                val total = listState.layoutInfo.totalItemsCount
                last.index >= total - 2
            }
        }

        // Held rather than derived from atBottom, because the answer has to be
        // the one from the instant the message landed. Deciding later reads the
        // scroll position after the user has already moved, and a thread that
        // jumps because they happened to scroll down while a message was in
        // flight is exactly the behaviour this exists to prevent.
        var pending by remember { mutableStateOf<String?>(null) }
        var seen by remember { mutableIntStateOf(timeline.size) }

        LaunchedEffect(timeline.size) {
            if (timeline.size <= seen) {
                // The thread shrank, or this is the first composition. Nothing
                // arrived, so nothing should move.
                seen = timeline.size
                return@LaunchedEffect
            }
            val arrival = timeline.lastOrNull() as? TimelineItem.Bubble
            val incoming = arrival?.message?.outgoing == false
            seen = timeline.size

            when {
                // Anything we sent ourselves always scrolls: the user pressed
                // send, so they are looking at the bottom by definition.
                arrival != null && !incoming -> {
                    pending = null
                    listState.animateScrollToItem(timeline.lastIndex)
                }
                atBottom -> {
                    pending = null
                    listState.animateScrollToItem(timeline.lastIndex)
                }
                incoming -> pending = arrival.message.body.take(46).let {
                    if (arrival.message.body.length > 46) it.trimEnd() + "…" else it
                }
            }
        }

        // Reading down to the end answers the notice, so it should not need
        // dismissing as well.
        LaunchedEffect(atBottom) { if (atBottom) pending = null }

        Box(Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(
                    start = Space.lg, end = Space.lg, top = 14.dp, bottom = Space.md,
                ),
                verticalArrangement = Arrangement.spacedBy(Space.sm),
            ) {
                items(timeline, onRetry)
            }

            NewMessagePill(
                visible = pending != null,
                preview = pending.orEmpty(),
                onClick = {
                    pending = null
                    scope.launch { listState.animateScrollToItem(timeline.lastIndex) }
                },
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 14.dp),
            )
        }

        Composer(onSend)
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.items(
    timeline: List<TimelineItem>,
    onRetry: (Long) -> Unit,
) {
    timeline.forEachIndexed { index, item ->
        when (item) {
            is TimelineItem.EncryptionNotice -> item(key = "notice-$index") { EncryptionNotice() }
            is TimelineItem.DayDivider -> item(key = "day-$index") {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { Pill(item.label) }
            }
            is TimelineItem.Bubble -> item(key = "msg-${item.message.id}") { MessageBubble(item.message, onRetry) }
        }
    }
}

@Composable
private fun ConversationHeader(
    peerAci: String,
    peerName: String,
    /** Gateway-assigned; null until this device has the peer's keys. */
    peerAvatarSeed: ByteArray?,
    /** The emoji this device shows for the peer. Local only. */
    peerAvatarEmoji: String? = null,
    onBack: () -> Unit,
    onOpenProfile: () -> Unit,
) {
    Column(Modifier.background(theme.background).statusBarsPadding()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onOpenProfile)
                .height(58.dp)
                .padding(start = 6.dp, end = 14.dp),
        ) {
            Box(
                Modifier.size(40.dp, Space.minTouchTarget).clickable(onClick = onBack),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.ArrowBack, "Orqaga", tint = theme.accent, modifier = Modifier.size(24.dp))
            }

            // The one avatar the screen is built around, so this is the
            // one that gets a running decoder.
            Avatar(peerAvatarSeed, peerName, 38.dp, animated = true, emojiId = peerAvatarEmoji)
            Spacer(Modifier.width(11.dp))

            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    peerName,
                    style = MillyType.Name,
                    color = theme.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                // Encryption state sits where every other messenger puts "last
                // seen". There is no last seen here, and the space is better
                // spent saying something true about the conversation.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    LockGlyph(theme.accent)
                    Spacer(Modifier.width(5.dp))
                    Text(
                        "uchidan-uchigacha shifrlangan",
                        style = MillyType.Timestamp.copy(fontWeight = FontWeight.Medium),
                        color = theme.accent,
                    )
                }
            }
        }
        Box(Modifier.fillMaxWidth().height(Space.hairline).background(theme.hairline))
    }
}

@Composable
private fun EncryptionNotice() {
    Box(Modifier.fillMaxWidth().padding(bottom = Space.xs), contentAlignment = Alignment.Center) {
        Row(
            verticalAlignment = Alignment.Top,
            modifier = Modifier
                .widthIn(max = 310.dp)
                .clip(RoundedCornerShape(15.dp))
                .background(theme.noticeSurface)
                .padding(horizontal = 14.dp, vertical = Space.md),
        ) {
            LockGlyph(theme.accent, Modifier.padding(top = 3.dp), size = 16.dp)
            Spacer(Modifier.width(10.dp))
            Text(
                text = buildAnnotatedString {
                    append("Bu suhbatdagi xabarlar ")
                    withStyle(SpanStyle(color = theme.noticeStrong, fontWeight = FontWeight.SemiBold)) {
                        append("uchidan-uchigacha shifrlangan")
                    }
                    append(". Ularni hech kim — Smile ham — oʻqiy olmaydi.")
                },
                style = MillyType.Notice,
                color = theme.noticeText,
            )
        }
    }
}

@Composable
private fun MessageBubble(message: Message, onRetry: (Long) -> Unit = {}) {
    val outgoing = message.outgoing
    val shape = if (outgoing) {
        RoundedCornerShape(Radius.bubble, Radius.bubble, Radius.bubbleAnchor, Radius.bubble)
    } else {
        RoundedCornerShape(Radius.bubble, Radius.bubble, Radius.bubble, Radius.bubbleAnchor)
    }
    val background = if (outgoing) theme.bubbleOutgoing else theme.bubbleIncoming
    val content = if (outgoing) theme.onBubbleOutgoing else theme.onBubbleIncoming
    val meta = content.copy(alpha = if (outgoing) 0.70f else 0.55f)

    val retryable = message.delivery == DeliveryState.Failed

    Box(
        Modifier
            .fillMaxWidth()
            .then(
                // Tapping a failed message resends it. The alternative — a
                // toast that has already gone by the time the user looks —
                // loses the text, which is the one thing that must not happen.
                if (retryable) Modifier.clickable { onRetry(message.id) } else Modifier,
            ),
        contentAlignment = if (outgoing) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Column(
            Modifier
                .widthIn(max = 300.dp)
                .clip(shape)
                .background(background)
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            // Who wrote it, in a group. Without this a group thread is a
            // column of anonymous text: the same words mean different things
            // depending on which of eight people said them, and a reply can be
            // aimed at the wrong person entirely. Absent in a private thread,
            // where it would be the same name on every bubble.
            if (!outgoing && message.author != null) {
                Text(
                    message.author,
                    style = MillyType.Meta,
                    color = theme.accent,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(bottom = 3.dp),
                )
            }

            message.replyTo?.let { reply ->
                Row(Modifier.padding(bottom = 7.dp)) {
                    Box(
                        Modifier
                            .width(2.5.dp)
                            .heightIn(min = 32.dp)
                            .clip(CircleShape)
                            .background(content.copy(alpha = 0.5f)),
                    )
                    Spacer(Modifier.width(9.dp))
                    Column {
                        Text(
                            reply.author,
                            style = MillyType.Meta.copy(fontWeight = FontWeight.SemiBold),
                            color = content.copy(alpha = 0.95f),
                        )
                        Text(
                            reply.excerpt,
                            style = MillyType.Meta,
                            color = content.copy(alpha = 0.7f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }

            Text(message.body, style = MillyType.Body, color = content)

            // Aligned to the end rather than filled: fillMaxWidth here would
            // stretch the bubble to its maximum for every message, so a
            // two-word reply would occupy the same box as a full sentence.
            Row(
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.align(Alignment.End).padding(top = 3.dp),
            ) {
                Text(message.timestamp, style = MillyType.Timestamp, color = meta)
                when (message.delivery) {
                    null -> Unit
                    DeliveryState.Sending -> {
                        Spacer(Modifier.width(4.dp))
                        DeliveryTick(content.copy(alpha = 0.35f))
                    }
                    DeliveryState.Sent -> {
                        Spacer(Modifier.width(4.dp))
                        DeliveryTick(content.copy(alpha = 0.85f))
                    }
                    DeliveryState.Failed -> {
                        Spacer(Modifier.width(4.dp))
                        FailedMark(theme.danger)
                    }
                }
            }
        }
    }
}

/**
 * Input and send. Nothing else, deliberately: every affordance a messenger puts
 * here — a paperclip, a microphone, a sticker key — is an entry point for a
 * media decoder, and this app has none.
 */
@Composable
private fun Composer(onSend: (String) -> Unit) {
    var draft by remember { mutableStateOf("") }
    val canSend = draft.isNotBlank()

    // The glow is tied to focus rather than left running. An ambient animation
    // on a screen somebody is only reading is a frame every 16ms and a battery
    // complaint; while the keyboard is up the phone is already awake and busy,
    // which is the one moment it costs nothing.
    var focused by remember { mutableStateOf(false) }
    val glow by animateFloatAsState(
        targetValue = if (focused) 1f else 0f,
        animationSpec = tween(durationMillis = 420, easing = FastOutSlowInEasing),
        label = "composerGlow",
    )

    Column(Modifier.background(theme.background)) {
        Box(Modifier.fillMaxWidth().height(Space.hairline).background(theme.hairline))
        Row(
            verticalAlignment = Alignment.Bottom,
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Box(Modifier.weight(1f)) {
                // Sits under the field and bleeds past it, so the colour reads
                // as light coming from behind glass rather than as a border.
                if (glow > 0.01f) {
                    AmbientGlow(
                        intensity = glow,
                        // No negative padding to make it bleed: padding throws
                        // on negatives, and it is not needed anyway — the glow
                        // draws radial fields wider than this box and nothing
                        // above clips them.
                        modifier = Modifier.matchParentSize(),
                    )
                }
            Box(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 44.dp)
                    .clip(RoundedCornerShape(22.dp))
                    .background(theme.field.copy(alpha = 0.82f))
                    .border(
                        width = 1.dp,
                        brush = Brush.verticalGradient(
                            listOf(
                                Color.White.copy(alpha = 0.13f * (0.35f + glow * 0.65f)),
                                Color.White.copy(alpha = 0.03f),
                            ),
                        ),
                        shape = RoundedCornerShape(22.dp),
                    )
                    .padding(horizontal = 17.dp, vertical = 11.dp),
                contentAlignment = Alignment.CenterStart,
            ) {
                if (draft.isEmpty()) {
                    Text("Xabar", style = MillyType.Body, color = theme.textTertiary)
                }
                BasicTextField(
                    value = draft,
                    // Capped where the protocol caps it, and counted in bytes
                    // rather than characters: the modifier letters Uzbek is
                    // written with take two bytes each, so a 4096-character
                    // limit would let through a message the client then refuses
                    // to send. Refusing the keystroke is kinder than accepting
                    // the message and marking it failed forever — retrying a
                    // body that is too long fails every time, with nothing on
                    // screen saying why.
                    onValueChange = { candidate ->
                        if (candidate.toByteArray(Charsets.UTF_8).size <= Protocol.MAX_PLAINTEXT_BYTES) {
                            draft = candidate
                        }
                    },
                    textStyle = LocalTextStyle.current.merge(MillyType.Body).merge(
                        androidx.compose.ui.text.TextStyle(color = theme.textPrimary),
                    ),
                    cursorBrush = SolidColor(theme.accent),
                    // The keyboard is a third-party app with a network
                    // connection. Cloud keyboards learn from what is typed and
                    // upload it, which carries message plaintext straight past
                    // the encryption.
                    //
                    // Turning off autocorrect is the part that reliably helps:
                    // it stops this field feeding the IME's learned dictionary.
                    // The private option is a hint that some keyboards honour.
                    //
                    // The guaranteed control is EditorInfo's
                    // IME_FLAG_NO_PERSONALIZED_LEARNING, and Compose only sets
                    // that for password fields — which would mask the message.
                    // Closing this properly needs an AndroidView-hosted
                    // EditText; until then it is mitigated, not solved.
                    keyboardOptions = KeyboardOptions(
                        autoCorrectEnabled = false,
                        capitalization = KeyboardCapitalization.Sentences,
                        platformImeOptions = PlatformImeOptions("noPersonalizedLearning"),
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .onFocusChanged { focused = it.isFocused },
                )
            }
            }

            Spacer(Modifier.width(10.dp))

            Box(
                Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(if (canSend) theme.accent else theme.field)
                    .clickable(enabled = canSend) {
                        onSend(draft.trim())
                        draft = ""
                    },
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.Rounded.ArrowUpward,
                    "Yuborish",
                    tint = if (canSend) theme.onAccent else theme.textTertiary,
                    modifier = Modifier.size(21.dp),
                )
            }
        }
    }
}

/**
 * A safety-number change is the one event that can mean the relay put itself
 * in the middle of this conversation. It is also what an ordinary reinstall
 * looks like, so the wording says what happened and what to do rather than
 * accusing anyone — and it stays until the user has compared the number.
 */
@Composable
private fun IdentityChangedBanner(onOpenProfile: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(theme.dangerSurface)
            .clickable(onClick = onOpenProfile)
            .padding(horizontal = Space.lg, vertical = 12.dp),
    ) {
        Text(
            "Xavfsizlik raqami oʻzgardi. Yozishishdan oldin uni tekshiring.",
            style = MillyType.Notice,
            color = theme.danger,
            modifier = Modifier.weight(1f),
        )
    }
}

/**
 * The light behind the composer.
 *
 * Three soft radial fields drifting past each other — a mesh gradient, built
 * out of overlapping gradients rather than a blur because a real backdrop blur
 * needs RenderEffect on API 31, and this app supports API 26. Overlapping
 * radial falloff is already soft-edged, so nothing here needs blurring to look
 * diffused.
 *
 * The palette is the app's own Samarkand teal moving through periwinkle to
 * violet, not the pink-and-lavender that signals an AI assistant. This is a
 * messenger; the glow should say the field is live, not that a model is
 * listening.
 */
@Composable
private fun AmbientGlow(intensity: Float, modifier: Modifier = Modifier) {
    val transition = rememberInfiniteTransition(label = "ambient")
    val drift by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2f * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable<Float>(tween(11_000, easing = LinearEasing)),
        label = "drift",
    )
    // A slow breath on top of the drift, so the glow never sits perfectly
    // still without ever pulsing hard enough to pull the eye off the text.
    val breath by transition.animateFloat(
        initialValue = 0.86f,
        targetValue = 1.06f,
        animationSpec = infiniteRepeatable<Float>(
            animation = tween(3_400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "breath",
    )

    val tints = listOf(theme.accent, Color(0xFF8D9FFF), Color(0xFFB07CF3))

    Canvas(modifier) {
        val w = size.width
        val h = size.height
        if (w <= 0f || h <= 0f) return@Canvas
        val reach = h * 1.5f

        tints.forEachIndexed { index, tint ->
            val phase = drift + index * 2.094f
            val cx = w * (0.5f + 0.34f * kotlin.math.cos(phase)) 
            val cy = h * (0.5f + 0.30f * kotlin.math.sin(phase * 1.3f))
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        tint.copy(alpha = 0.42f * intensity),
                        tint.copy(alpha = 0.16f * intensity),
                        tint.copy(alpha = 0f),
                    ),
                    center = Offset(cx, cy),
                    radius = reach * breath,
                ),
                radius = reach * breath,
                center = Offset(cx, cy),
            )
        }
    }
}
