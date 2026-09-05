package uz.millygram.app.data

import android.content.Context
import java.io.Closeable
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uz.millygram.client.MillygramClient
import uz.millygram.client.MillygramOptions
import uz.millygram.client.MillygramRegisterOptions

/**
 * The bridge between the blocking client library and the UI.
 *
 * `MillygramClient` is deliberately synchronous — every call has bounded work
 * and the library should not impose a concurrency model on its callers. That
 * makes this layer's job explicit: keep all of it off the main thread, and
 * expose the result as state Compose can observe.
 */
class MillygramSession private constructor(
    private val client: MillygramClient,
    private val scope: CoroutineScope,
) : Closeable {

    val aci: String get() = client.aci
    val username: String get() = client.username

    private val _conversations = MutableStateFlow<List<ConversationState>>(emptyList())
    val conversations: StateFlow<List<ConversationState>> = _conversations.asStateFlow()

    private val _status = MutableStateFlow(Status.Offline)
    val status: StateFlow<Status> = _status.asStateFlow()

    /**
     * Raised when an envelope arrives from a known contact under an identity
     * key we did not pin. That is what a relay substituting keys looks like
     * from here, and it must reach the user rather than being counted as one
     * of the undecryptable envelopes every bucket member receives.
     */
    private val _identityWarnings = MutableStateFlow<Set<String>>(emptySet())
    val identityWarnings: StateFlow<Set<String>> = _identityWarnings.asStateFlow()

    enum class Status { Offline, Connecting, Online }

    /**
     * Message ids only have to be unique, and unique is the whole job: the
     * timeline keys its list on them, and Compose throws when two rows share a
     * key. Deriving them from the send time collided whenever two messages were
     * recorded in the same millisecond — two quick taps on send is enough.
     * They are deliberately not persisted; nothing outside a single run refers
     * to them.
     */
    private val nextId = java.util.concurrent.atomic.AtomicLong(1)

    private var subscription: Closeable? = null
    private var reconnectJob: Job? = null
    private var dropped = CompletableDeferred<Unit>()

    /** Set by [close] so the retry loop does not fight a deliberate shutdown. */
    @Volatile
    private var closed = false

    init {
        _conversations.value = loadContacts()
    }

    /**
     * Opens the delivery socket and keeps it open.
     *
     * The retry loop is the point. A socket that drops and is never rebuilt
     * leaves the app looking idle while messages pile up on the relay, and the
     * user has no way to tell that from nobody having written. Backoff is
     * capped low enough that recovery from an ordinary mobile-network gap is
     * measured in seconds.
     */
    fun connect() {
        if (reconnectJob?.isActive == true) return
        reconnectJob = scope.launch {
            var backoffMs = MIN_BACKOFF_MS
            var failing = false
            while (isActive && !closed) {
                // "Connecting" is shown only while the first attempt of an
                // outage is in flight. Once an attempt has failed, the state
                // stays "offline" through every retry: an attempt that is
                // always in progress would leave the banner permanently
                // hopeful, which is the opposite of what the user needs to
                // know — that nothing is arriving right now.
                if (!failing) _status.value = Status.Connecting

                val opened = runCatching {
                    client.onIdentityMismatch = { senderAci ->
                        _identityWarnings.update { it + senderAci }
                    }
                    subscription = client.connect(
                        onMessage = { incoming ->
                            record(
                                peerAci = incoming.senderAci,
                                body = incoming.body,
                                sentAt = incoming.sentAt,
                                outgoing = false,
                            )
                        },
                        onDisconnected = { dropped.complete(Unit) },
                    )
                }.isSuccess

                if (!opened) {
                    failing = true
                    _status.value = Status.Offline
                    delay(backoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
                    continue
                }

                failing = false
                _status.value = Status.Online
                backoffMs = MIN_BACKOFF_MS

                // Park until the socket reports it is gone, then rebuild it.
                dropped.await()
                dropped = CompletableDeferred()
                subscription?.runCatching { close() }
                subscription = null
                if (closed) break
                _status.value = Status.Offline
            }
        }
    }

    /** Clears the warning once the user has looked at the safety number. */
    fun acknowledgeIdentityWarning(peerAci: String) {
        _identityWarnings.update { it - peerAci }
    }

    /**
     * Resolves a username, sends, and records the message locally. Failures
     * surface as a thrown exception on the caller's coroutine rather than a
     * silently dropped message — a messenger that loses text without saying so
     * is worse than one that reports the failure.
     */
    suspend fun send(recipient: String, body: String) = withContext(Dispatchers.IO) {
        val target = if (recipient.contains('-')) {
            recipient
        } else {
            // A failure here means the name does not exist, and there is no
            // conversation to attach it to; it goes back to the caller.
            val entry = client.resolveUsername(recipient)
            rememberContact(entry.aci, recipient)
            entry.aci
        }

        // Recorded before the network is touched, so the message is on screen
        // while it is in flight and stays there if the send fails. A messenger
        // that erases text it could not deliver is worse than one that says so.
        val id = record(
            peerAci = target,
            body = body,
            sentAt = System.currentTimeMillis(),
            outgoing = true,
            delivery = Delivery.Sending,
        )

        try {
            client.send(target, body)
            markDelivery(target, id, Delivery.Sent)
        } catch (failure: Throwable) {
            markDelivery(target, id, Delivery.Failed)
            throw failure
        }
    }

    /** Re-sends a message the relay never accepted. */
    suspend fun retry(peerAci: String, messageId: Long) = withContext(Dispatchers.IO) {
        val message = messagesFor(peerAci).firstOrNull { it.id == messageId } ?: return@withContext
        markDelivery(peerAci, messageId, Delivery.Sending)
        try {
            client.send(peerAci, message.body)
            markDelivery(peerAci, messageId, Delivery.Sent)
        } catch (failure: Throwable) {
            markDelivery(peerAci, messageId, Delivery.Failed)
            throw failure
        }
    }

    private fun markDelivery(peerAci: String, messageId: Long, delivery: Delivery) {
        _conversations.update { current ->
            current.map { conversation ->
                if (conversation.aci != peerAci) {
                    conversation
                } else {
                    conversation.copy(
                        messages = conversation.messages.map {
                            if (it.id == messageId) it.copy(delivery = delivery) else it
                        },
                    )
                }
            }
        }
        persistContacts()
    }

    suspend fun safetyNumber(peerAci: String): String = withContext(Dispatchers.IO) {
        client.safetyNumber(peerAci)
    }

    fun messagesFor(peerAci: String): List<MessageState> =
        _conversations.value.firstOrNull { it.aci == peerAci }?.messages.orEmpty()

    /* ---- contacts and history ---- */

    private fun record(
        peerAci: String,
        body: String,
        sentAt: Long,
        outgoing: Boolean,
        delivery: Delivery? = null,
    ): Long {
        val id = nextId.getAndIncrement()
        _conversations.update { current ->
            val existing = current.firstOrNull { it.aci == peerAci }
            val message = MessageState(
                id = id,
                body = body,
                sentAt = sentAt,
                outgoing = outgoing,
                delivery = delivery,
            )

            val updated = existing?.copy(messages = existing.messages + message)
                ?: ConversationState(
                    aci = peerAci,
                    username = contactName(peerAci),
                    messages = listOf(message),
                )

            (current.filterNot { it.aci == peerAci } + updated).sortedByDescending {
                it.messages.lastOrNull()?.sentAt ?: 0
            }
        }
        persistContacts()
        return id
    }

    private fun contactName(aci: String): String =
        client.getAppData("contact:$aci") ?: aci.take(8)

    private fun rememberContact(aci: String, username: String) {
        client.putAppData("contact:$aci", username)
    }

    /**
     * History lives in the encrypted vault rather than a separate database, so
     * it inherits the same key and the same at-rest protection as session
     * state. It is a plain JSON blob because the volume is small and a second
     * schema would be a second thing to get wrong.
     */
    private fun persistContacts() {
        val array = JSONArray()
        for (conversation in _conversations.value) {
            array.put(
                JSONObject().apply {
                    put("aci", conversation.aci)
                    put("username", conversation.username)
                    put(
                        "messages",
                        JSONArray().apply {
                            // Keep the tail. A device that has been running for
                            // months should not carry an unbounded blob it must
                            // decrypt on every write.
                            for (message in conversation.messages.takeLast(MAX_HISTORY)) {
                                put(
                                    JSONObject().apply {
                                        put("body", message.body)
                                        put("sentAt", message.sentAt)
                                        put("outgoing", message.outgoing)
                                        // A message still in flight when the
                                        // process died did not reach the relay,
                                        // so it reloads as failed rather than
                                        // as quietly sent.
                                        put(
                                            "delivery",
                                            when (message.delivery) {
                                                null -> "none"
                                                Delivery.Sent -> "sent"
                                                else -> "failed"
                                            },
                                        )
                                    },
                                )
                            }
                        },
                    )
                },
            )
        }
        client.putAppData("history", array.toString())
    }

    private fun loadContacts(): List<ConversationState> {
        val raw = client.getAppData("history") ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).map { index ->
                val entry = array.getJSONObject(index)
                val messages = entry.getJSONArray("messages")
                ConversationState(
                    aci = entry.getString("aci"),
                    username = entry.getString("username"),
                    messages = (0 until messages.length()).map { messageIndex ->
                        val message = messages.getJSONObject(messageIndex)
                        MessageState(
                            id = nextId.getAndIncrement(),
                            body = message.getString("body"),
                            sentAt = message.getLong("sentAt"),
                            outgoing = message.getBoolean("outgoing"),
                            delivery = when (message.optString("delivery")) {
                                "sent" -> Delivery.Sent
                                "failed" -> Delivery.Failed
                                else -> null
                            },
                        )
                    },
                )
            }
        }.getOrDefault(emptyList())
    }

    override fun close() {
        closed = true
        // Wake the retry loop so it observes `closed` and stops, rather than
        // parking forever on a socket that will never drop again.
        dropped.complete(Unit)
        reconnectJob?.cancel()
        subscription?.runCatching { close() }
        client.close()
        _status.value = Status.Offline
    }

    companion object {
        private const val MAX_HISTORY = 500
        private const val MIN_BACKOFF_MS = 1_000L
        private const val MAX_BACKOFF_MS = 30_000L
        private const val DATABASE = "millygram.db"

        fun exists(context: Context): Boolean =
            context.getDatabasePath(DATABASE).let(File::exists)

        suspend fun register(
            context: Context,
            username: String,
            passphrase: String,
            serverUrl: String,
            obliviousRelayUrl: String? = null,
        ): MillygramSession = withContext(Dispatchers.IO) {
            val client = MillygramClient.register(
                MillygramRegisterOptions(
                    username = username,
                    base = MillygramOptions(
                        context = context,
                        databaseName = DATABASE,
                        passphrase = passphrase,
                        serverUrl = serverUrl,
                        obliviousRelayUrl = obliviousRelayUrl,
                    ),
                ),
            )
            MillygramSession(client, CoroutineScope(SupervisorJob() + Dispatchers.IO))
        }

        suspend fun open(
            context: Context,
            passphrase: String,
            serverUrl: String,
            obliviousRelayUrl: String? = null,
        ): MillygramSession = withContext(Dispatchers.IO) {
            val client = MillygramClient.open(
                MillygramOptions(
                    context = context,
                    databaseName = DATABASE,
                    passphrase = passphrase,
                    serverUrl = serverUrl,
                    obliviousRelayUrl = obliviousRelayUrl,
                ),
            )
            MillygramSession(client, CoroutineScope(SupervisorJob() + Dispatchers.IO))
        }
    }
}

data class ConversationState(
    val aci: String,
    val username: String,
    val messages: List<MessageState>,
)

/**
 * What the sender can actually observe about an outgoing message.
 *
 * There is no delivery receipt and no read receipt in the protocol, so those
 * states do not exist here. [Sent] means the relay accepted the envelope, and
 * that is the furthest anything on this device can honestly claim.
 */
enum class Delivery { Sending, Sent, Failed }

data class MessageState(
    val id: Long,
    val body: String,
    val sentAt: Long,
    val outgoing: Boolean,
    /** Null for incoming messages, where it has no meaning. */
    val delivery: Delivery? = null,
)
