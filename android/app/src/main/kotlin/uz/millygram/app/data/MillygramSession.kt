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
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
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

    private val _groups = MutableStateFlow<List<GroupSummary>>(emptyList())
    val groups: StateFlow<List<GroupSummary>> = _groups.asStateFlow()

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
    /**
     * Emitted when a message arrives from someone else.
     *
     * Carries who it came from and nothing else. What the notification says is
     * decided where it is shown, and it deliberately does not say much: this
     * app keeps itself out of screenshots and the recents thumbnail, and
     * putting the text of a message on the lock screen would undo that for the
     * one person most likely to be looking over the user's shoulder.
     */
    private val _arrivals = MutableSharedFlow<Arrival>(extraBufferCapacity = 32)
    val arrivals: SharedFlow<Arrival> = _arrivals.asSharedFlow()

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

    /** Last index written, so an unchanged conversation list costs no write. */
    private var lastIndex: String = ""

    private var subscription: Closeable? = null
    private var reconnectJob: Job? = null
    /** Set by [close] so the retry loop does not fight a deliberate shutdown. */
    @Volatile
    private var closed = false

    init {
        _conversations.value = loadContacts()
        refreshGroups()
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

                // One deferred per attempt, created before the socket that
                // completes it. Sharing a single field across attempts left a
                // gap between awaiting it and replacing it: a close arriving in
                // that gap completed the deferred nobody was waiting on any
                // more, and the loop then waited for ever on the fresh one —
                // parked, with the status still reading online while nothing
                // arrived. Seen exactly that way, twice, before this.
                val thisAttempt = CompletableDeferred<Unit>()

                val opened = runCatching {
                    client.onIdentityMismatch = { senderAci ->
                        _identityWarnings.update { it + senderAci }
                    }
                    subscription = client.connect(
                        onMessage = { incoming ->
                            learnName(incoming.senderAci, incoming.senderUsername)
                            // A message that arrived in a group belongs to the
                            // group's thread, not to a private one with whoever
                            // sent it. Filing it by sender put group traffic in
                            // a one-to-one conversation, where it read as a
                            // private message from that person -- and the reply
                            // would have gone only to them.
                            val group = incoming.groupId
                            val sender = contactName(incoming.senderAci)
                            if (group != null) {
                                refreshGroups()
                                record(
                                    peerAci = groupThreadKey(group),
                                    body = incoming.body,
                                    sentAt = incoming.sentAt,
                                    outgoing = false,
                                    author = sender,
                                )
                            } else {
                                record(
                                    peerAci = incoming.senderAci,
                                    body = incoming.body,
                                    sentAt = incoming.sentAt,
                                    outgoing = false,
                                )
                            }
                            _arrivals.tryEmit(
                                Arrival(
                                    peerAci = if (group != null) groupThreadKey(group) else incoming.senderAci,
                                    username = if (group != null) groupLabel(group) else sender,
                                    body = incoming.body,
                                ),
                            )
                        },
                        onDisconnected = { thisAttempt.complete(Unit) },
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
                thisAttempt.await()
                subscription?.runCatching { close() }
                subscription = null
                if (closed) break
                _status.value = Status.Offline
            }
        }
    }

    /**
     * Accepts a contact's new identity: unpins the old key so messages can flow
     * again, and clears the warning. Dismissing the warning without this leaves
     * the conversation silently broken, so the two belong together.
     */
    /** See MillygramClient.exportBackup. */
    suspend fun exportBackup(passphrase: String): ByteArray = withContext(Dispatchers.IO) {
        client.exportBackup(passphrase)
    }

    /**
     * Attaches or removes the number this account can be recovered with.
     *
     * See MillygramClient.attachRecoveryNumber for what it costs. The screen
     * that offers this has to say the same thing, because the gateway learning
     * a number is the one part of this app that is not deniable.
     */
    suspend fun attachRecoveryNumber(phoneNumber: String) = withContext(Dispatchers.IO) {
        client.attachRecoveryNumber(phoneNumber)
    }

    suspend fun detachRecoveryNumber() = withContext(Dispatchers.IO) {
        client.detachRecoveryNumber()
    }

    /** The number attached to this account, or null if none is. */
    val recoveryNumber: String? get() = client.recoveryNumber

    /**
     * The avatar seed the gateway published for an account.
     *
     * Null until this device has fetched that account's keys, which is the only
     * place a seed ever comes from. Nothing a peer sends can reach this.
     */
    fun avatarSeed(peerAci: String): ByteArray? = client.avatarSeed(peerAci)

    /**
     * Which emoji stands in for a contact — on this device, and nowhere else.
     *
     * This is a note the phone's owner keeps about somebody, in the same way
     * the local name for a contact is. It is never sent, never received, and
     * has no field on the wire: a peer cannot see what they look like here, and
     * cannot influence it. That is what keeps an animated avatar from being the
     * profile-photo problem again — the bytes ship in the APK, and the only
     * person who chooses among them is holding the phone.
     *
     * Stored through putAppData, so it lives in the encrypted vault with
     * everything else and leaves with the account when the account is erased.
     */
    fun avatarEmoji(peerAci: String): String =
        client.getAppData(avatarEmojiKey(peerAci)) ?: DEFAULT_AVATAR_EMOJI

    fun setAvatarEmoji(peerAci: String, emojiId: String) {
        client.putAppData(avatarEmojiKey(peerAci), emojiId)
        // The list holds this on its state so it is not read per row per frame,
        // which means the write has to reach that copy too or the choice would
        // not appear until the next launch.
        _conversations.update { list ->
            list.map { if (it.aci == peerAci) it.copy(avatarEmoji = emojiId) else it }
        }
    }

    private fun avatarEmojiKey(peerAci: String) = "avatarEmoji:$peerAci"

    /** How well this device protects the vault, and how its environment looks. */
    fun securityPosture(): MillygramClient.SecurityPosture = client.securityPosture()

    /** This account's own seed, so the profile shows what contacts see. */
    val ownAvatarSeed: ByteArray? get() = client.ownAvatarSeed

    /**
     * Whether opening the app asks for a fingerprint.
     *
     * Off by default. The people this app is for are coming from Telegram,
     * which asks for nothing, and a messenger that demands a fingerprint before
     * it will show a message is a messenger they stop using. It is offered
     * rather than imposed, and the people who want it know why they want it.
     */
    private val _requireUnlock = MutableStateFlow(client.getAppData(REQUIRE_UNLOCK) == "1")

    /**
     * Observable, not a plain property read.
     *
     * The screen that gates the app has to react the moment this is switched
     * on. Reading it once at composition meant turning it on and switching away
     * left the app unlocked when you came back — the observer that re-locks was
     * never registered, because at the time it was composed the setting was
     * still off. A lock with that hole in it is worse than no lock, because the
     * user believes it is there.
     */
    val requireUnlockState: StateFlow<Boolean> = _requireUnlock.asStateFlow()

    var requireUnlock: Boolean
        get() = _requireUnlock.value
        set(value) {
            client.putAppData(REQUIRE_UNLOCK, if (value) "1" else "0")
            _requireUnlock.value = value
        }

    /**
     * Clears the unread mark for a conversation.
     *
     * Called when its screen is open, not when a notification is tapped: the
     * mark is about whether the messages have been looked at, and a tap that
     * opens the app is the start of that rather than proof of it.
     */
    fun markRead(peerAci: String) {
        var changed = false
        _conversations.update { list ->
            list.map { conversation ->
                if (conversation.aci == peerAci && conversation.unread > 0) {
                    changed = true
                    conversation.copy(unread = 0)
                } else {
                    conversation
                }
            }
        }
        if (changed) _conversations.value.firstOrNull { it.aci == peerAci }?.let(::persist)
    }

    /** What notifications are allowed to say. Persisted, so it survives a restart. */
    var notificationDetail: NotificationDetail
        get() = NotificationDetail.parse(client.getAppData(NOTIFY_DETAIL))
        set(value) = client.putAppData(NOTIFY_DETAIL, value.stored)

    suspend fun acceptNewIdentity(peerAci: String) = withContext(Dispatchers.IO) {
        client.forgetPeer(peerAci)
        _identityWarnings.update { it - peerAci }
    }

    /**
     * Resolves a username, sends, and records the message locally. Failures
     * surface as a thrown exception on the caller's coroutine rather than a
     * silently dropped message — a messenger that loses text without saying so
     * is worse than one that reports the failure.
     */
    /** Every group this device is in, newest state first. */
    fun refreshGroups() {
        _groups.value = runCatching {
            client.groups().map { GroupSummary(it.groupId, it.name, it.members) }
        }.getOrDefault(emptyList())
    }

    /** The group's name, or its identifier if this device has not learned one. */
    private fun groupLabel(groupId: String): String =
        runCatching { client.group(groupId)?.name }.getOrNull()?.takeIf { it.isNotBlank() }
            ?: groupId.take(8)

    suspend fun createGroup(name: String, memberAcis: List<String>): String = withContext(Dispatchers.IO) {
        val created = client.createGroup(name, memberAcis)
        refreshGroups()
        created.groupId
    }

    suspend fun setGroupMembers(groupId: String, members: List<String>) = withContext(Dispatchers.IO) {
        client.updateGroupMembers(groupId, members)
        refreshGroups()
    }

    /**
     * Leaves a group and drops its thread from this device.
     *
     * There is no "delete for everyone" and there cannot be: a group is a label
     * a few clients agree to use, held by each of them, with no server-side
     * object to remove. Leaving tells the others so they stop addressing this
     * device, and forgets the local copy. The others keep theirs.
     */
    suspend fun leaveGroup(groupId: String) = withContext(Dispatchers.IO) {
        client.leaveGroup(groupId)
        val key = groupThreadKey(groupId)
        client.putAppData("$HISTORY_PREFIX$key", "")
        _conversations.update { current -> current.filterNot { it.aci == key } }
        persistIndex()
        refreshGroups()
    }

    suspend fun sendToGroup(groupId: String, body: String) = withContext(Dispatchers.IO) {
        val key = groupThreadKey(groupId)
        // Recorded before the network is touched, for the same reason a private
        // send is: the message stays on screen if the send fails.
        val id = record(key, body, System.currentTimeMillis(), outgoing = true, delivery = Delivery.Sending)
        try {
            client.sendToGroup(groupId, body)
            markDelivery(key, id, Delivery.Sent)
        } catch (failure: Throwable) {
            markDelivery(key, id, Delivery.Failed)
            throw failure
        }
    }

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
        _conversations.value.firstOrNull { it.aci == peerAci }?.let(::persist)
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
        author: String? = null,
    ): Long {
        val id = nextId.getAndIncrement()
        // A group thread has no ACI behind it, so none of the per-contact
        // lookups below mean anything for one: there is no avatar seed to fetch
        // and no contact name to take. Its label is the group's name instead.
        val groupId = groupIdOf(peerAci)
        _conversations.update { current ->
            val existing = current.firstOrNull { it.aci == peerAci }
            val message = MessageState(
                id = id,
                body = body,
                sentAt = sentAt,
                outgoing = outgoing,
                delivery = delivery,
                author = author,
            )

            // The name is taken fresh every time rather than only when the
            // conversation is created. A handle learned from a later message —
            // the first one carried none, or the sender was a stranger until
            // now — would otherwise be stored and never shown, leaving the
            // conversation labelled with the identifier for good.
            // Only what arrives counts. Echoing our own sends into the unread
            // total would light up the row for a message the user just typed.
            val bump = if (message.outgoing) 0 else 1
            val label = if (groupId != null) groupLabel(groupId) else contactName(peerAci)
            val seed = if (groupId != null) null else client.avatarSeed(peerAci)
            val emoji = if (groupId != null) GROUP_AVATAR_EMOJI else avatarEmoji(peerAci)
            val updated = existing?.copy(
                username = label,
                avatarSeed = existing.avatarSeed ?: seed,
                avatarEmoji = emoji,
                messages = existing.messages + message,
                unread = existing.unread + bump,
                groupId = groupId,
            ) ?: ConversationState(
                aci = peerAci,
                username = label,
                avatarSeed = seed,
                avatarEmoji = emoji,
                messages = listOf(message),
                unread = bump,
                groupId = groupId,
            )

            (current.filterNot { it.aci == peerAci } + updated).sortedByDescending {
                it.messages.lastOrNull()?.sentAt ?: 0
            }
        }
        _conversations.value.firstOrNull { it.aci == peerAci }?.let(::persist)
        persistIndex()
        return id
    }

    /**
     * Adopts the handle a sender claims, once the directory agrees it is theirs.
     *
     * Sealed sender proves which account a message came from; it says nothing
     * about what that account is called, and the claim rides inside the
     * ciphertext where anyone could write anything. So it is checked the only
     * way round that exists — handle to identifier — and a mismatch is simply
     * ignored, leaving the conversation labelled by identifier as before.
     * Without this a first message from someone shows eight characters of hex,
     * which is not a person's name in any language.
     */
    private fun learnName(peerAci: String, claimed: String?) {
        if (claimed == null) return
        if (client.getAppData("contact:$peerAci") != null) return
        runCatching {
            if (client.resolveUsername(claimed).aci == peerAci) rememberContact(peerAci, claimed)
        }
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
    /**
     * Writes one conversation, not all of them.
     *
     * History lives in the encrypted vault rather than a separate database, so
     * it inherits the same key and the same at-rest protection as session
     * state. It used to live in a single blob holding every conversation, which
     * was rewritten and re-encrypted whenever anything changed — three times
     * for each message sent. That cost grew with the whole history rather than
     * with the part that changed: measured on an emulator, a hundred messages
     * cost 4ms to write and two thousand cost 41ms, so thirty conversations at
     * the retention cap reached most of a second per message sent, and several
     * times that on the hardware this is built for.
     *
     * Each conversation is its own entry now, with an index listing them, so a
     * write costs what one conversation costs and nothing more.
     */
    private fun persist(conversation: ConversationState) {
        val entry = JSONObject().apply {
            put("username", conversation.username)
            put("unread", conversation.unread)
            conversation.groupId?.let { put("groupId", it) }
            put(
                "messages",
                JSONArray().apply {
                    // Keep the tail. A device that has been running for months
                    // should not carry an unbounded blob it must decrypt on
                    // every write.
                    for (message in conversation.messages.takeLast(MAX_HISTORY)) {
                        put(
                            JSONObject().apply {
                                put("body", message.body)
                                put("sentAt", message.sentAt)
                                put("outgoing", message.outgoing)
                                message.author?.let { put("author", it) }
                                // A message still in flight when the process
                                // died did not reach the relay, so it reloads
                                // as failed rather than as quietly sent.
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
        }
        client.putAppData("$HISTORY_PREFIX${conversation.aci}", entry.toString())
    }

    /** The list of conversations there are entries for. Written only when it changes. */
    private fun persistIndex() {
        val index = JSONArray().apply { _conversations.value.forEach { put(it.aci) } }
        if (index.toString() != lastIndex) {
            client.putAppData(HISTORY_INDEX, index.toString())
            lastIndex = index.toString()
        }
    }

    private fun loadContacts(): List<ConversationState> {
        migrateSingleBlobHistory()

        val index = runCatching { JSONArray(client.getAppData(HISTORY_INDEX) ?: "[]") }
            .getOrDefault(JSONArray())
        lastIndex = index.toString()

        return (0 until index.length()).mapNotNull { position ->
            runCatching {
                val aci = index.getString(position)
                val entry = JSONObject(client.getAppData("$HISTORY_PREFIX$aci") ?: return@runCatching null)
                readConversation(aci, entry)
            }.getOrNull()
        }
    }

    private fun readConversation(aci: String, entry: JSONObject): ConversationState {
        val messages = entry.getJSONArray("messages")
        return ConversationState(
            aci = aci,
            username = entry.getString("username"),
            // optString, not getString: every entry written before groups
            // existed lacks this key, and reading those must not throw.
            groupId = entry.optString("groupId").takeIf { it.isNotBlank() },
            avatarSeed = if (groupIdOf(aci) != null) null else client.avatarSeed(aci),
            avatarEmoji = if (groupIdOf(aci) != null) GROUP_AVATAR_EMOJI else avatarEmoji(aci),
            unread = entry.optInt("unread", 0),
            messages = (0 until messages.length()).map { index ->
                val message = messages.getJSONObject(index)
                MessageState(
                    id = nextId.getAndIncrement(),
                    body = message.getString("body"),
                    sentAt = message.getLong("sentAt"),
                    outgoing = message.getBoolean("outgoing"),
                    author = message.optString("author").takeIf { it.isNotBlank() },
                    delivery = when (message.optString("delivery")) {
                        "sent" -> Delivery.Sent
                        "failed" -> Delivery.Failed
                        else -> null
                    },
                )
            },
        )
    }

    /**
     * Moves an account off the single-blob layout the first time it is opened.
     *
     * Existing installs have their whole history under one key. Reading it once
     * and writing it back out per conversation is the only migration needed;
     * the old entry is then emptied so this does not run again.
     */
    private fun migrateSingleBlobHistory() {
        val legacy = client.getAppData(LEGACY_HISTORY)?.takeIf { it.isNotBlank() } ?: return
        runCatching {
            val split = splitLegacyHistory(legacy)
            for ((aci, entry) in split.conversations) client.putAppData("$HISTORY_PREFIX$aci", entry)
            client.putAppData(HISTORY_INDEX, split.index)
        }
        client.putAppData(LEGACY_HISTORY, "")
    }

    override fun close() {
        closed = true
        // Cancelling is what wakes the loop now; there is no shared deferred
        // left to complete, which is the point.
        reconnectJob?.cancel()
        subscription?.runCatching { close() }
        client.close()
        _status.value = Status.Offline
    }

    companion object {
        /**
         * What a contact shows before anybody chooses anything for them.
         *
         * The brand's own face, so an account that has never been customised
         * still looks like this app rather than like a placeholder.
         */
        const val DEFAULT_AVATAR_EMOJI = "grinning_face"

        /** Groups get one mark rather than a per-contact choice; there is no one face for several people. */
        const val GROUP_AVATAR_EMOJI = "people_hugging"

        private const val MAX_HISTORY = 500
        private const val HISTORY_PREFIX = "history:"

        /**
         * A group thread's key in the same history store private threads use.
         *
         * A group is not an account and has no ACI, but it is a thread with
         * messages, an unread count and a place in the same sorted list. Giving
         * it a key in the same namespace means the storage, the index, the
         * retention cap and the migration all work on it unchanged. The prefix
         * is what keeps the two apart, and an ACI is a UUID so it can never
         * collide with one.
         */
        private const val GROUP_THREAD_PREFIX = "group:"

        fun groupThreadKey(groupId: String) = "$GROUP_THREAD_PREFIX$groupId"

        fun groupIdOf(threadKey: String): String? =
            threadKey.removePrefix(GROUP_THREAD_PREFIX).takeIf { threadKey.startsWith(GROUP_THREAD_PREFIX) }
        private const val HISTORY_INDEX = "history:index"
        /** The single blob every conversation used to share. Read once, then emptied. */
        private const val LEGACY_HISTORY = "history"
        private const val NOTIFY_DETAIL = "notifyDetail"
        private const val REQUIRE_UNLOCK = "requireUnlock"
        private const val MIN_BACKOFF_MS = 1_000L
        private const val MAX_BACKOFF_MS = 30_000L
        private const val DATABASE = "millygram.db"

        /**
         * Rebuilds an account from a backup, then opens it.
         *
         * The old handset must not keep running afterwards. Both would hold the
         * same sessions and the ratchet would advance in two places at once,
         * which breaks the conversation for whichever message loses the race —
         * silently, since a message that will not decrypt is dropped the same
         * way as one meant for somebody else.
         */
        suspend fun restore(
            context: Context,
            backup: ByteArray,
            passphrase: String,
            serverUrl: String,
            obliviousRelayUrl: String? = null,
        ): MillygramSession = withContext(Dispatchers.IO) {
            MillygramClient.restoreBackup(context, DATABASE, backup, passphrase)
            open(context, passphrase, serverUrl, obliviousRelayUrl)
        }

        /** Opens without asking, when the device can. Null when it cannot. */
        suspend fun resume(
            context: Context,
            serverUrl: String,
            obliviousRelayUrl: String? = null,
        ): MillygramSession? = withContext(Dispatchers.IO) {
            val client = MillygramClient.openWithDeviceKey(
                MillygramOptions(
                    context = context,
                    databaseName = DATABASE,
                    passphrase = "",
                    serverUrl = serverUrl,
                    obliviousRelayUrl = obliviousRelayUrl,
                ),
            ) ?: return@withContext null
            MillygramSession(client, CoroutineScope(SupervisorJob() + Dispatchers.IO))
        }

        /** True when a launch can skip the passphrase screen entirely. */
        fun canResume(context: Context): Boolean = MillygramClient.canOpenWithDeviceKey(
            MillygramOptions(
                context = context,
                databaseName = DATABASE,
                passphrase = "",
                serverUrl = "",
            ),
        )

        /**
         * Takes away this device's standing permission to open the vault.
         *
         * The account is not touched. What is destroyed is the shortcut — the
         * keystore-wrapped copy of the data key that lets a launch skip the
         * passphrase — so that after this the only way back in is the thing
         * the user knows rather than the thing the phone holds.
         *
         * That distinction is the entire value of the lock in Settings. The
         * phone is handed over unlocked in this country as a matter of routine,
         * at a checkpoint or across a desk, and a lock that leaves the device
         * still able to open the vault by itself is a lock that a second tap on
         * the app icon walks straight through. Zeroing the key in memory is not
         * enough for that; the wrapping on disk has to go too.
         *
         * Blocking: it writes to SQLite and talks to the keystore, so it wants
         * a background thread. See MillygramClient.forgetDeviceKey for what it
         * costs and what it deliberately leaves alone.
         */
        fun forgetDeviceKey(context: Context) = MillygramClient.forgetDeviceKey(context, DATABASE)

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

        /** Asks the gateway to text a code to a number. */
        suspend fun startRecovery(serverUrl: String, phoneNumber: String) = withContext(Dispatchers.IO) {
            MillygramClient.startRecovery(serverUrl, phoneNumber)
        }

        /**
         * Takes back a handle on a new handset, with new keys.
         *
         * The result is deliberately not the old account: no history, and a
         * safety number every contact will see change. See
         * MillygramClient.recoverWithCode.
         */
        suspend fun recover(
            context: Context,
            phoneNumber: String,
            code: String,
            passphrase: String,
            serverUrl: String,
            obliviousRelayUrl: String? = null,
        ): MillygramSession = withContext(Dispatchers.IO) {
            val client = MillygramClient.recoverWithCode(
                MillygramOptions(
                    context = context,
                    databaseName = DATABASE,
                    passphrase = passphrase,
                    serverUrl = serverUrl,
                    obliviousRelayUrl = obliviousRelayUrl,
                ),
                phoneNumber,
                code,
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
    /** The thread key: a peer's ACI, or [MillygramSession.groupThreadKey] for a group. */
    val aci: String,
    val username: String,
    /** Gateway-assigned; null until this device has fetched the peer's keys. */
    val avatarSeed: ByteArray? = null,
    /**
     * The emoji this device shows for the contact. Carried on the state rather
     * than read per row, because a list asks for this on every frame it scrolls
     * and the vault is encrypted.
     */
    val avatarEmoji: String = MillygramSession.DEFAULT_AVATAR_EMOJI,
    val messages: List<MessageState>,
    /** Set when this thread is a group rather than one other person. */
    val groupId: String? = null,
    /** Arrived since this conversation was last opened. */
    val unread: Int = 0,
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
    /**
     * Who wrote it, for a group thread. Null in a private one, where the
     * question has one answer and printing it on every bubble is noise.
     */
    val author: String? = null,
)

/** A group as the list screen needs it: enough to draw a row, nothing more. */
data class GroupSummary(
    val groupId: String,
    val name: String,
    val members: List<String>,
)

/** The single-blob history split into the per-conversation form that replaced it. */
data class SplitHistory(val index: String, val conversations: List<Pair<String, String>>)

/**
 * Pure so it can be tested off a device.
 *
 * Existing installs keep their whole history under one key, and this is the
 * only thing standing between those people and an empty message list after an
 * update — worth being able to check without a handset in the loop.
 */
fun splitLegacyHistory(legacy: String): SplitHistory {
    val array = JSONArray(legacy)
    val acis = JSONArray()
    val conversations = mutableListOf<Pair<String, String>>()
    for (position in 0 until array.length()) {
        val entry = array.getJSONObject(position)
        val aci = entry.getString("aci")
        acis.put(aci)
        conversations += aci to JSONObject().apply {
            put("username", entry.getString("username"))
            put("messages", entry.getJSONArray("messages"))
        }.toString()
    }
    return SplitHistory(acis.toString(), conversations)
}

/** A message that has just arrived, for whatever wants to announce it. */
data class Arrival(val peerAci: String, val username: String, val body: String)

/**
 * How much a notification may say.
 *
 * A locked phone never shows more than that something arrived, whichever of
 * these is chosen — that part is not configurable, because the person most
 * likely to read someone's lock screen is standing next to them. This governs
 * what is shown once the phone is unlocked.
 */
enum class NotificationDetail(val stored: String) {
    /** Who wrote, and what they wrote. */
    NameAndMessage("full"),

    /** Who wrote, and nothing else. */
    NameOnly("name"),

    /** That something arrived. */
    Nothing("none"),
    ;

    companion object {
        /** Name only by default: enough to act on, without putting words anywhere. */
        fun parse(stored: String?): NotificationDetail =
            entries.firstOrNull { it.stored == stored } ?: NameOnly
    }
}
