package uz.millygram.client

import java.util.UUID
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.groups.state.SenderKeyStore
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * A single object that implements every store interface libsignal wants from
 * a sealed-sender cipher. Each interface is delegated to the matching real
 * store; group support (`SenderKeyStore`) is left as an explicit
 * "unsupported" — the app is text-only 1:1 for now, and a silent stub here
 * would let a future accidental call succeed against nothing.
 */
class CombinedProtocolStore(private val stores: ProtocolStores) : SignalProtocolStore {

    /* IdentityKeyStore */
    override fun getIdentityKeyPair(): IdentityKeyPair = stores.identity.getIdentityKeyPair()
    override fun getLocalRegistrationId(): Int = stores.identity.getLocalRegistrationId()
    override fun saveIdentity(address: SignalProtocolAddress, key: IdentityKey): IdentityKeyStore.IdentityChange =
        stores.identity.saveIdentity(address, key)
    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        key: IdentityKey,
        direction: IdentityKeyStore.Direction,
    ): Boolean = stores.identity.isTrustedIdentity(address, key, direction)
    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? = stores.identity.getIdentity(address)

    /* SessionStore */
    override fun loadSession(address: SignalProtocolAddress): SessionRecord = stores.session.loadSession(address)
    @Throws(NoSessionException::class)
    override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> =
        stores.session.loadExistingSessions(addresses)
    override fun getSubDeviceSessions(name: String): List<Int> = stores.session.getSubDeviceSessions(name)
    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) =
        stores.session.storeSession(address, record)
    override fun containsSession(address: SignalProtocolAddress): Boolean = stores.session.containsSession(address)
    override fun deleteSession(address: SignalProtocolAddress) = stores.session.deleteSession(address)
    override fun deleteAllSessions(name: String) = stores.session.deleteAllSessions(name)

    /* PreKeyStore */
    override fun loadPreKey(id: Int): PreKeyRecord = stores.preKey.loadPreKey(id)
    override fun storePreKey(id: Int, record: PreKeyRecord) = stores.preKey.storePreKey(id, record)
    override fun containsPreKey(id: Int): Boolean = stores.preKey.containsPreKey(id)
    override fun removePreKey(id: Int) = stores.preKey.removePreKey(id)

    /* SignedPreKeyStore */
    override fun loadSignedPreKey(id: Int): SignedPreKeyRecord = stores.signedPreKey.loadSignedPreKey(id)
    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> = stores.signedPreKey.loadSignedPreKeys()
    override fun storeSignedPreKey(id: Int, record: SignedPreKeyRecord) =
        stores.signedPreKey.storeSignedPreKey(id, record)
    override fun containsSignedPreKey(id: Int): Boolean = stores.signedPreKey.containsSignedPreKey(id)
    override fun removeSignedPreKey(id: Int) = stores.signedPreKey.removeSignedPreKey(id)

    /* KyberPreKeyStore */
    override fun loadKyberPreKey(id: Int): KyberPreKeyRecord = stores.kyberPreKey.loadKyberPreKey(id)
    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> = stores.kyberPreKey.loadKyberPreKeys()
    override fun storeKyberPreKey(id: Int, record: KyberPreKeyRecord) =
        stores.kyberPreKey.storeKyberPreKey(id, record)
    override fun containsKyberPreKey(id: Int): Boolean = stores.kyberPreKey.containsKyberPreKey(id)
    override fun markKyberPreKeyUsed(kyberPreKeyId: Int, signedPreKeyId: Int, baseKey: ECPublicKey) =
        stores.kyberPreKey.markKyberPreKeyUsed(kyberPreKeyId, signedPreKeyId, baseKey)

    /* SenderKeyStore — groups are not supported */
    override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: UUID, record: SenderKeyRecord) {
        throw UnsupportedOperationException("group messaging is not implemented")
    }
    override fun loadSenderKey(sender: SignalProtocolAddress, distributionId: UUID): SenderKeyRecord? {
        throw UnsupportedOperationException("group messaging is not implemented")
    }
}
