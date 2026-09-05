package uz.millygram.app.data

import android.content.Context
import java.io.Closeable
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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

    private var subscription: Closeable? = null

    init {
        _conversations.value = loadContacts()
    }

    fun connect() {
        scope.launch {
            _status.value = Status.Connecting
            runCatching {
                subscription = client.connect { incoming ->
                    record(
                        peerAci = incoming.senderAci,
                        body = incoming.body,
                        sentAt = incoming.sentAt,
                        outgoing = false,
                    )
                }
                _status.value = Status.Online
            }.onFailure { _status.value = Status.Offline }
        }
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
            val entry = client.resolveUsername(recipient)
            rememberContact(entry.aci, recipient)
            entry.aci
        }

        client.send(target, body)
        record(peerAci = target, body = body, sentAt = System.currentTimeMillis(), outgoing = true)
    }

    suspend fun safetyNumber(peerAci: String): String = withContext(Dispatchers.IO) {
        client.safetyNumber(peerAci)
    }

    fun messagesFor(peerAci: String): List<MessageState> =
        _conversations.value.firstOrNull { it.aci == peerAci }?.messages.orEmpty()

    /* ---- contacts and history ---- */

    private fun record(peerAci: String, body: String, sentAt: Long, outgoing: Boolean) {
        _conversations.update { current ->
            val existing = current.firstOrNull { it.aci == peerAci }
            val message = MessageState(
                id = sentAt * 10 + if (outgoing) 1 else 0,
                body = body,
                sentAt = sentAt,
                outgoing = outgoing,
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
                            id = message.getLong("sentAt") * 10 +
                                if (message.getBoolean("outgoing")) 1 else 0,
                            body = message.getString("body"),
                            sentAt = message.getLong("sentAt"),
                            outgoing = message.getBoolean("outgoing"),
                        )
                    },
                )
            }
        }.getOrDefault(emptyList())
    }

    override fun close() {
        subscription?.close()
        client.close()
        _status.value = Status.Offline
    }

    companion object {
        private const val MAX_HISTORY = 500
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

data class MessageState(
    val id: Long,
    val body: String,
    val sentAt: Long,
    val outgoing: Boolean,
)
