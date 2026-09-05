package uz.millygram.app.ui

import androidx.compose.runtime.Immutable

/**
 * What the UI renders. Deliberately not the client's own types: a screen should
 * not be able to reach a private key or a session record by accident, and a
 * separate model makes that structural rather than a matter of discipline.
 */
@Immutable
data class Conversation(
    val aci: String,
    val displayName: String,
    val username: String,
    val preview: String,
    val timestamp: String,
    val unread: Int = 0,
    /** True when the last message in the preview was sent by us. */
    val outgoing: Boolean = false,
    val previewPrefix: String? = null,
)

@Immutable
data class Message(
    val id: Long,
    val body: String,
    val timestamp: String,
    val outgoing: Boolean,
    val delivered: Boolean = true,
    val replyTo: ReplyContext? = null,
)

@Immutable
data class ReplyContext(val author: String, val excerpt: String)

@Immutable
data class Contact(val aci: String, val displayName: String, val username: String)

/** A day divider or an inline system notice, laid out between messages. */
sealed interface TimelineItem {
    data class Bubble(val message: Message) : TimelineItem
    data class DayDivider(val label: String) : TimelineItem
    data object EncryptionNotice : TimelineItem
}

@Immutable
data class Account(
    val displayName: String,
    val username: String,
    val safetyNumber: String,
    val deviceCount: Int,
    val keyTransparencyVerified: Boolean,
    val readReceipts: Boolean,
    val screenLock: Boolean,
    val language: String,
    val theme: String,
    val buildHash: String,
)
