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
    /** Gateway-assigned avatar seed; null until this device has the keys. */
    val avatarSeed: ByteArray? = null,
    /** The emoji this device shows for the contact. Local, never sent. */
    val avatarEmoji: String? = null,
)

/**
 * The only states a sender can honestly be shown.
 *
 * There is no delivery receipt and no read receipt anywhere in the protocol,
 * so there is no state here that claims either. [Sent] means the relay
 * accepted the envelope; whether it was fetched, decrypted or read is
 * unknowable from this device, and a second tick would be an invention.
 */
/**
 * A group as the list needs it.
 *
 * [members] are ACIs, which is what the protocol carries; the screen resolves
 * them to names for display. Kept as identifiers here so a row can be drawn
 * before every member's name is known -- a group can contain somebody this
 * device has never exchanged a message with, and waiting on that would leave
 * the row blank.
 */
data class Group(
    val groupId: String,
    val name: String,
    val members: List<String>,
    val preview: String = "",
    val timestamp: String = "",
    val unread: Int = 0,
)

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
    /**
     * Who wrote it, in a group. Null in a private thread, where the question
     * has one answer and printing it on every bubble is noise.
     */
    val author: String? = null,
)

@Immutable
data class ReplyContext(val author: String, val excerpt: String)

@Immutable
data class Contact(
    val aci: String,
    val displayName: String,
    val username: String,
    /** Gateway-assigned avatar seed; null until this device has the keys. */
    val avatarSeed: ByteArray? = null,
)

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
    /** What a notification is allowed to say, already in words. */
    val notificationDetail: String,
    /** The number this account can be taken back with, or null if none is set. */
    val recoveryNumber: String?,
    val language: String,
    val theme: String,
    val buildHash: String,
    /** Gateway-assigned avatar seed; null until this device has the keys. */
    val avatarSeed: ByteArray? = null,
    /** Whether opening the app asks for a fingerprint. */
    val requireUnlock: Boolean = false,
    /** Empty when the device can do it; otherwise why it cannot. */
    val unlockUnavailable: String? = null,
    /** True when the vault key sits in a discrete secure element. */
    val strongBox: Boolean = false,
    /** True when the device has secure-element hardware at all. */
    val strongBoxHardware: Boolean = false,
    /** Self-reported environment read: "clean" or a flag list. */
    val environment: String = "clean",
)
