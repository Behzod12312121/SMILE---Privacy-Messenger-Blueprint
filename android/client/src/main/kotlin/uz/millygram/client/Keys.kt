package uz.millygram.client

import java.security.SecureRandom
import org.json.JSONArray
import org.json.JSONObject
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import uz.millygram.protocol.Protocol

/**
 * Prekey material generation. Everything the server needs to hand out to
 * peers so they can start a session is produced here and stored under the
 * matching prekey store; the private halves never leave the device.
 */
object Keys {

    /** libsignal registration ids are 14 bits and zero is reserved. */
    fun generateRegistrationId(): Int {
        val random = SecureRandom()
        // Range is [1, 0x3fff]. nextInt(0x3fff) returns [0, 0x3ffe]; +1 gives [1, 0x3fff].
        return random.nextInt(0x3fff) + 1
    }

    data class SignedPreKeyMaterial(val keyId: Int, val publicKeyB64: String, val signatureB64: String)

    fun generateSignedPreKey(identity: IdentityKeyPair, keyId: Int, stores: ProtocolStores): SignedPreKeyMaterial {
        val keyPair = ECKeyPair.Companion.generate()
        val signature = identity.privateKey.calculateSignature(keyPair.publicKey.serialize())
        val record = SignedPreKeyRecord(keyId, System.currentTimeMillis(), keyPair, signature)
        stores.signedPreKey.storeSignedPreKey(keyId, record)
        return SignedPreKeyMaterial(keyId, Protocol.b64(keyPair.publicKey.serialize()), Protocol.b64(signature))
    }

    /**
     * The Kyber prekey is what makes the initial handshake post-quantum: X25519
     * and ML-KEM secrets are both mixed into the root key, so archived traffic
     * needs both broken to read.
     */
    fun generateKyberPreKey(identity: IdentityKeyPair, keyId: Int, stores: ProtocolStores): SignedPreKeyMaterial {
        val keyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val signature = identity.privateKey.calculateSignature(keyPair.publicKey.serialize())
        val record = KyberPreKeyRecord(keyId, System.currentTimeMillis(), keyPair, signature)
        stores.kyberPreKey.storeKyberPreKey(keyId, record)
        return SignedPreKeyMaterial(keyId, Protocol.b64(keyPair.publicKey.serialize()), Protocol.b64(signature))
    }

    data class OneTimeMaterial(val keyId: Int, val publicKeyB64: String)

    fun generateOneTimePreKeys(firstId: Int, count: Int, stores: ProtocolStores): List<OneTimeMaterial> {
        val out = ArrayList<OneTimeMaterial>(count)
        for (offset in 0 until count) {
            val keyId = firstId + offset
            val keyPair = ECKeyPair.Companion.generate()
            stores.preKey.storePreKey(keyId, PreKeyRecord(keyId, keyPair))
            out += OneTimeMaterial(keyId, Protocol.b64(keyPair.publicKey.serialize()))
        }
        return out
    }
}

/** JSON helpers for the registration payload shape the server expects. */
internal fun Keys.SignedPreKeyMaterial.toJson(): JSONObject = JSONObject().apply {
    put("keyId", keyId)
    put("publicKey", publicKeyB64)
    put("signature", signatureB64)
}

internal fun Keys.OneTimeMaterial.toJson(): JSONObject = JSONObject().apply {
    put("keyId", keyId)
    put("publicKey", publicKeyB64)
}

internal fun List<Keys.OneTimeMaterial>.toJsonArray(): JSONArray =
    JSONArray().apply { for (item in this@toJsonArray) put(item.toJson()) }
