package uz.millygram.client

import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.KyberPreKeyStore
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyStore
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SessionStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyStore

/**
 * The five libsignal protocol stores, backed by the encrypted `LocalStore`.
 * Everything sensitive — session state, identity pins, prekey private material
 * — is sealed under the vault before it touches SQLite.
 *
 * These implementations follow the Java store contract exactly: `loadSession`
 * returns a fresh empty `SessionRecord` rather than null when no session
 * exists, `loadPreKey` throws `InvalidKeyIdException` rather than returning
 * null. Kotlin nullability is not enough of a guarantee here — the libsignal
 * runtime relies on the specific behaviour.
 */

private fun addressKey(address: SignalProtocolAddress): String = "${address.name}.${address.deviceId}"

class MillygramSessionStore(private val store: LocalStore) : SessionStore {

    override fun loadSession(address: SignalProtocolAddress): SessionRecord {
        val raw = store.readRecord("sessions", addressKey(address)) ?: return SessionRecord()
        return SessionRecord(raw)
    }

    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> {
        val records = ArrayList<SessionRecord>(addresses.size)
        for (address in addresses) {
            val raw = store.readRecord("sessions", addressKey(address))
                ?: throw NoSessionException("no session for ${addressKey(address)}")
            records += SessionRecord(raw)
        }
        return records
    }

    override fun getSubDeviceSessions(name: String): List<Int> {
        // Multi-device is not modelled yet; every account uses device id 1.
        // Returning an empty list here means libsignal will not try to fan out
        // to devices we have not registered.
        return emptyList()
    }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        store.writeRecord("sessions", addressKey(address), record.serialize())
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean =
        store.readRecord("sessions", addressKey(address)) != null

    override fun deleteSession(address: SignalProtocolAddress) {
        store.deleteRecord("sessions", addressKey(address))
    }

    override fun deleteAllSessions(name: String) {
        // Deleting a whole name at once would require a range delete which the
        // current LocalStore surface does not expose. Sessions per device are
        // deleted individually via deleteSession; the account rewrap flow does
        // not go through this method.
        throw UnsupportedOperationException("deleteAllSessions is not implemented")
    }
}

class MillygramIdentityStore(
    private val store: LocalStore,
    private val identity: IdentityKeyPair,
    private val registrationId: Int,
) : IdentityKeyStore {

    override fun getIdentityKeyPair(): IdentityKeyPair = identity

    override fun getLocalRegistrationId(): Int = registrationId

    override fun saveIdentity(address: SignalProtocolAddress, key: IdentityKey): IdentityKeyStore.IdentityChange {
        val addressString = addressKey(address)
        val existing = store.readIdentity(addressString)
        val incoming = key.serialize()

        store.writeIdentity(addressString, incoming)

        if (existing == null) return IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        return if (existing.contentEquals(incoming)) {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        } else {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }
    }

    /**
     * Trust on first use, and refuse silently-changed keys afterwards. A
     * changed identity is exactly what server-side impersonation looks like:
     * accepting it here would defeat the whole safety-number mechanism.
     */
    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        key: IdentityKey,
        direction: IdentityKeyStore.Direction,
    ): Boolean {
        val existing = store.readIdentity(addressKey(address)) ?: return true
        return existing.contentEquals(key.serialize())
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? =
        store.readIdentity(addressKey(address))?.let { IdentityKey(it, 0) }
}

class MillygramPreKeyStore(private val store: LocalStore) : PreKeyStore {

    override fun loadPreKey(id: Int): PreKeyRecord {
        val raw = store.readRecord("prekeys", id.toLong())
            ?: throw InvalidKeyIdException("missing one-time prekey $id")
        return PreKeyRecord(raw)
    }

    override fun storePreKey(id: Int, record: PreKeyRecord) {
        store.writeRecord("prekeys", id.toLong(), record.serialize())
    }

    override fun containsPreKey(id: Int): Boolean = store.readRecord("prekeys", id.toLong()) != null

    override fun removePreKey(id: Int) {
        store.deleteRecord("prekeys", id.toLong())
    }
}

class MillygramSignedPreKeyStore(private val store: LocalStore) : SignedPreKeyStore {

    override fun loadSignedPreKey(id: Int): SignedPreKeyRecord {
        val raw = store.readRecord("signed_prekeys", id.toLong())
            ?: throw InvalidKeyIdException("missing signed prekey $id")
        return SignedPreKeyRecord(raw)
    }

    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> {
        // Not needed for the current send/receive flow; a full enumeration
        // would require iterating the SQLite table and is added when the
        // rotation flow that needs it lands.
        throw UnsupportedOperationException("loadSignedPreKeys is not implemented")
    }

    override fun storeSignedPreKey(id: Int, record: SignedPreKeyRecord) {
        store.writeRecord("signed_prekeys", id.toLong(), record.serialize())
    }

    override fun containsSignedPreKey(id: Int): Boolean =
        store.readRecord("signed_prekeys", id.toLong()) != null

    override fun removeSignedPreKey(id: Int) {
        store.deleteRecord("signed_prekeys", id.toLong())
    }
}

class MillygramKyberPreKeyStore(private val store: LocalStore) : KyberPreKeyStore {

    override fun loadKyberPreKey(id: Int): KyberPreKeyRecord {
        val raw = store.readRecord("kyber_prekeys", id.toLong())
            ?: throw InvalidKeyIdException("missing kyber prekey $id")
        return KyberPreKeyRecord(raw)
    }

    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> {
        throw UnsupportedOperationException("loadKyberPreKeys is not implemented")
    }

    override fun storeKyberPreKey(id: Int, record: KyberPreKeyRecord) {
        store.writeRecord("kyber_prekeys", id.toLong(), record.serialize())
    }

    override fun containsKyberPreKey(id: Int): Boolean =
        store.readRecord("kyber_prekeys", id.toLong()) != null

    /**
     * @param baseKey exists in the signature only because a duplicate base key
     * within one signed prekey window means somebody has reused a one-time
     * value. libsignal enforces the check; we just record that the kyber
     * prekey was used.
     */
    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) {
        store.markKyberUsed(kyberPreKeyId.toLong())
    }
}

class ProtocolStores(
    val session: MillygramSessionStore,
    val identity: MillygramIdentityStore,
    val preKey: MillygramPreKeyStore,
    val signedPreKey: MillygramSignedPreKeyStore,
    val kyberPreKey: MillygramKyberPreKeyStore,
) {
    companion object {
        fun forAccount(store: LocalStore, identity: IdentityKeyPair, registrationId: Int): ProtocolStores =
            ProtocolStores(
                session = MillygramSessionStore(store),
                identity = MillygramIdentityStore(store, identity, registrationId),
                preKey = MillygramPreKeyStore(store),
                signedPreKey = MillygramSignedPreKeyStore(store),
                kyberPreKey = MillygramKyberPreKeyStore(store),
            )
    }
}
