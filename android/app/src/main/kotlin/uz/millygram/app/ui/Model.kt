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

/**
 * The only states a sender can honestly be shown.
 *
 * There is no delivery receipt and no read receipt anywhere in the protocol,
 * so there is no state here that claims either. [Sent] means the relay
 * accepted the envelope; whether it was fetched, decrypted or read is
 * unknowable from this device, and a second tick would be an invention.
 */
enum class DeliveryState { Sending, Sent, Failed }

/** Whether the delivery socket is up. Shown so silence is never ambiguous. */
enum class ConnectionState { Online, Connecting, Offline }

@Immutable
data class Message(
    val id: Long,
    val body: String,
    val timestamp: String,
    val outgoing: Boolean,
    /** Null for incoming messages, where it has no meaning. */
    val delivery: DeliveryState? = null,
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
    val screenLock: Boolean,
    val language: String,
    val theme: String,
    val buildHash: String,
)
