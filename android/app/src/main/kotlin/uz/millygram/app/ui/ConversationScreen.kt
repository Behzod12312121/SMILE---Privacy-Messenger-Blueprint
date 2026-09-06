package uz.millygram.app.ui

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
        ConversationHeader(peerAci, peerName, onBack, onOpenProfile)

        // Shown when a message arrived from this contact signed by an identity
        // key we had not pinned. Everything below it in the thread predates a
        // key we cannot vouch for, so the warning sits above the timeline
        // rather than inside it, and does not go away on its own.
        if (identityChanged) IdentityChangedBanner(onOpenProfile)

        LazyColumn(
            modifier = Modifier.weight(1f).fillMaxWidth(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                start = Space.lg, end = Space.lg, top = 14.dp, bottom = Space.md,
            ),
            verticalArrangement = Arrangement.spacedBy(Space.sm),
        ) {
            items(timeline, onRetry)
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

            Avatar(peerAci, peerName, 38.dp)
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
                    append(". Ularni hech kim — MillyGram ham — oʻqiy olmaydi.")
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

    Column(Modifier.background(theme.background)) {
        Box(Modifier.fillMaxWidth().height(Space.hairline).background(theme.hairline))
        Row(
            verticalAlignment = Alignment.Bottom,
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Box(
                Modifier
                    .weight(1f)
                    .heightIn(min = 44.dp)
                    .clip(RoundedCornerShape(22.dp))
                    .background(theme.field)
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
                    modifier = Modifier.fillMaxWidth(),
                )
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
