package uz.millygram.client

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.Closeable
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import uz.millygram.protocol.Protocol
import uz.millygram.protocol.Vault

/**
 * The encrypted local vault. Every row of every user-facing table is sealed
 * with AES-256-GCM under a data key that is itself wrapped by a
 * scrypt-derived key from the user's passphrase. Every value is bound to its
 * own row through AAD, so a valid ciphertext moved between rows fails to
 * authenticate rather than succeeding silently.
 *
 * This is a straight port of the Node implementation in
 * `packages/client/src/store.ts` and shares its schema. The Kotlin SQLite
 * calls are the only Android-specific code here; the encryption envelope lives
 * in the shared `uz.millygram.protocol.Vault`.
 */
class LocalStore private constructor(
    private val db: SQLiteDatabase,
    private val dek: ByteArray,
) : Closeable {

    override fun close() {
        dek.fill(0)
        db.close()
    }

    /* ---- metadata ---- */

    fun getMeta(key: String): ByteArray? = readEncrypted("meta", "key", "value", key)

    fun setMeta(key: String, value: ByteArray) = writeEncrypted("meta", "key", "value", key, value)

    fun getMetaString(key: String): String? = getMeta(key)?.let { String(it, Charsets.UTF_8) }

    fun setMetaString(key: String, value: String) = setMeta(key, value.toByteArray(Charsets.UTF_8))

    fun getMetaLong(key: String): Long? = getMetaString(key)?.toLong()

    fun setMetaLong(key: String, value: Long) = setMetaString(key, value.toString())

    /* ---- session / identity / prekeys ---- */

    fun readRecord(table: String, id: String): ByteArray? = readEncrypted(table, "address", "record", id)

    fun writeRecord(table: String, id: String, record: ByteArray) =
        writeEncrypted(table, "address", "record", id, record)

    fun readRecord(table: String, id: Long): ByteArray? =
        readEncrypted(table, "id", "record", id.toString())

    fun writeRecord(table: String, id: Long, record: ByteArray) =
        writeEncrypted(table, "id", "record", id.toString(), record)

    fun deleteRecord(table: String, id: String) {
        requireKnown(table)
        db.delete(table, "address = ?", arrayOf(id))
    }

    fun deleteRecord(table: String, id: Long) {
        requireKnown(table)
        db.delete(table, "id = ?", arrayOf(id.toString()))
    }

    fun readIdentity(address: String): ByteArray? = readEncrypted("identities", "address", "key", address)

    fun writeIdentity(address: String, key: ByteArray) =
        writeEncrypted("identities", "address", "key", address, key)

    fun markKyberUsed(id: Long) {
        db.execSQL("UPDATE kyber_prekeys SET used = 1 WHERE id = ?", arrayOf<Any>(id))
    }

    /* ---- internals ---- */

    /**
     * Table and column names cannot be bound as SQL parameters, so they are
     * interpolated — and interpolation is only safe while the inputs are
     * provably constant. Checking them against the schema means a future caller
     * that reaches this with a computed name fails loudly instead of building a
     * query out of it.
     */
    private fun requireKnown(table: String, vararg columns: String) {
        require(table in ALLOWED_TABLES) { "unknown table: $table" }
        for (column in columns) require(column in ALLOWED_COLUMNS) { "unknown column: $column" }
    }

    private fun readEncrypted(table: String, idColumn: String, valueColumn: String, id: String): ByteArray? {
        requireKnown(table, idColumn, valueColumn)
        db.query(table, arrayOf(valueColumn), "$idColumn = ?", arrayOf(id), null, null, null).use { cursor ->
            if (!cursor.moveToFirst()) return null
            val sealed = cursor.getBlob(0)
            return Vault.open(dek, Vault.aad(table, id), sealed)
        }
    }

    private fun writeEncrypted(
        table: String,
        idColumn: String,
        valueColumn: String,
        id: String,
        plaintext: ByteArray,
    ) {
        requireKnown(table, idColumn, valueColumn)
        val sealed = Vault.seal(dek, Vault.aad(table, id), plaintext)
        db.execSQL(
            "INSERT INTO $table ($idColumn, $valueColumn) VALUES (?, ?) " +
                "ON CONFLICT($idColumn) DO UPDATE SET $valueColumn = excluded.$valueColumn",
            arrayOf<Any>(id, sealed),
        )
    }

    /**
     * Writes the whole vault out under a passphrase of the user's choosing.
     *
     * The sealed values are copied exactly as they are stored. Each one is
     * bound by its associated data to the table and row it belongs to, and the
     * backup preserves both, so nothing has to be decrypted to move it and a
     * value cannot be replanted somewhere else on the way back in. What the
     * passphrase protects is the data key; everything else is already
     * unreadable without it.
     */
    fun exportBackup(passphrase: String): ByteArray {
        val salt = Vault.randomSalt()
        val params = Vault.KdfParameters()
        val kek = Vault.deriveKey(passphrase, salt, params)
        val wrapped = Vault.seal(kek, Vault.aad("vault", "dek"), dek)
        kek.fill(0)

        val rows = JSONArray()
        val digestRows = mutableListOf<Protocol.BackupRow>()
        for (table in ALLOWED_TABLES) {
            val idColumn = idColumnFor(table)
            val valueColumn = valueColumnFor(table)
            db.query(table, arrayOf(idColumn, valueColumn), null, null, null, null, null).use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getString(0)
                    val value = cursor.getBlob(1)
                    digestRows += Protocol.BackupRow(table, id, value)
                    rows.put(
                        JSONObject().apply {
                            put("table", table)
                            put("id", id)
                            put("value", android.util.Base64.encodeToString(value, BASE64))
                        },
                    )
                }
            }
        }

        return JSONObject().apply {
            put("format", BACKUP_FORMAT)
            put("kdfN", params.n)
            put("kdfR", params.r)
            put("kdfP", params.p)
            put("salt", android.util.Base64.encodeToString(salt, BASE64))
            put("wrappedKey", android.util.Base64.encodeToString(wrapped, BASE64))
            put("rows", rows)
            // Binds the list to the data key. Without it the rows could be
            // deleted from the file and the restore would still succeed.
            put(
                "rowsSeal",
                android.util.Base64.encodeToString(
                    Vault.seal(dek, Vault.aad("backup", "rows"), Protocol.backupRowsDigest(digestRows)),
                    BASE64,
                ),
            )
        }.toString().toByteArray(Charsets.UTF_8)
    }

    companion object {
        private const val SCHEMA_VERSION = 2
        private const val BACKUP_FORMAT = "millygram-backup-v2"

        /**
         * The format before the row list was authenticated. Recognised only so
         * that somebody holding one is told what happened, rather than being
         * shown "not a MillyGram backup" for a file that plainly is one.
         *
         * Not accepted. Accepting it would hand back the whole point: an
         * attacker who can touch the file could strip the seal, relabel it as
         * the older format, and have the stripped rows restored anyway.
         */
        private const val BACKUP_FORMAT_UNAUTHENTICATED = "millygram-backup-v1"
        private const val BASE64 = android.util.Base64.NO_WRAP

        private fun idColumnFor(table: String): String = when (table) {
            "meta" -> "key"
            "sessions", "identities" -> "address"
            else -> "id"
        }

        private fun valueColumnFor(table: String): String = when (table) {
            "meta" -> "value"
            "identities" -> "key"
            else -> "record"
        }

        /**
         * Rebuilds a vault from a backup.
         *
         * The passphrase that protected the backup becomes the passphrase of
         * the restored vault, because carrying two of them around is a way to
         * lose both. Refuses to write over an account that already exists: a
         * restore that silently replaced the vault on the handset would be a
         * very expensive mis-tap.
         */
        fun importBackup(context: Context, name: String, backup: ByteArray, passphrase: String) {
            val parsed = JSONObject(String(backup, Charsets.UTF_8))
            val format = parsed.optString("format")
            require(format == BACKUP_FORMAT) {
                if (format == BACKUP_FORMAT_UNAUTHENTICATED) {
                    "this backup was written before backups authenticated their contents, so rows could be " +
                        "removed from it without detection; export a fresh one from the device that holds the account"
                } else {
                    "not a MillyGram backup"
                }
            }

            val salt = android.util.Base64.decode(parsed.getString("salt"), BASE64)
            val wrapped = android.util.Base64.decode(parsed.getString("wrappedKey"), BASE64)
            val params = Vault.KdfParameters(
                n = parsed.getInt("kdfN"),
                r = parsed.getInt("kdfR"),
                p = parsed.getInt("kdfP"),
            )
            // Checked before scrypt is asked to honour them. These numbers come
            // out of the file, and scrypt sizes its working memory from them.
            Vault.requireSaneKdf(params)

            // Checked before anything is written, so a wrong passphrase costs
            // nothing but the derivation.
            val kek = Vault.deriveKey(passphrase, salt, params)
            val dek = try {
                Vault.open(kek, Vault.aad("vault", "dek"), wrapped)
            } catch (t: Throwable) {
                throw IllegalStateException("wrong passphrase for this backup", t)
            } finally {
                kek.fill(0)
            }

            // The row list is checked as a whole, before a single row is
            // written.
            //
            // Every row is sealed on its own, so nobody without the passphrase
            // can read one or write a new one. Removing rows needed neither:
            // the file simply carried fewer and the restore finished without
            // complaint. Stripping the `identities` rows is the damaging
            // version — they are the pinned contact keys, and a device that
            // comes back without them silently accepts the next key it is
            // offered for a contact it had already verified.
            val rows = parsed.getJSONArray("rows")
            try {
                val expected = Vault.open(
                    dek,
                    Vault.aad("backup", "rows"),
                    android.util.Base64.decode(parsed.getString("rowsSeal"), BASE64),
                )
                val actual = Protocol.backupRowsDigest(
                    (0 until rows.length()).map { index ->
                        val row = rows.getJSONObject(index)
                        Protocol.BackupRow(
                            table = row.getString("table"),
                            id = row.getString("id"),
                            value = android.util.Base64.decode(row.getString("value"), BASE64),
                        )
                    },
                )
                require(MessageDigest.isEqual(expected, actual)) {
                    "this backup's contents do not match what it was exported with"
                }
            } catch (e: IllegalArgumentException) {
                throw e
            } catch (t: Throwable) {
                throw IllegalStateException("this backup's contents could not be verified", t)
            } finally {
                dek.fill(0)
            }

            require(!context.getDatabasePath(name).exists()) {
                "this device already holds an account; remove it before restoring"
            }

            val helper = OpenHelper(context.applicationContext, name)
            helper.setWriteAheadLoggingEnabled(true)
            val db = helper.writableDatabase
            db.beginTransaction()
            try {
                db.execSQL(
                    "INSERT INTO vault (id, kdf_salt, wrapped_key, kdf_n, kdf_r, kdf_p) VALUES (1, ?, ?, ?, ?, ?)",
                    arrayOf<Any>(salt, wrapped, params.n, params.r, params.p),
                )
                for (index in 0 until rows.length()) {
                    val row = rows.getJSONObject(index)
                    val table = row.getString("table")
                    require(table in ALLOWED_TABLES) { "unknown table in backup: $table" }
                    db.execSQL(
                        "INSERT INTO $table (${idColumnFor(table)}, ${valueColumnFor(table)}) VALUES (?, ?)",
                        arrayOf<Any>(
                            row.getString("id"),
                            android.util.Base64.decode(row.getString("value"), BASE64),
                        ),
                    )
                }
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
                db.close()
            }
        }

        private val ALLOWED_TABLES = setOf(
            "meta", "sessions", "identities", "prekeys", "signed_prekeys", "kyber_prekeys",
        )
        private val ALLOWED_COLUMNS = setOf("key", "value", "address", "record", "id")

        /**
         * Opens a vault without a passphrase, using the key the device holds.
         *
         * Returns null when there is nothing to open with — no vault, no device
         * wrapping yet, no screen lock, or a key the system dropped because the
         * lock was removed. Every one of those is an ordinary reason to fall
         * back to asking, not an error.
         */
        fun openWithDeviceKey(context: Context, name: String): LocalStore? {
            if (!context.getDatabasePath(name).exists()) return null

            val helper = OpenHelper(context.applicationContext, name)
            helper.setWriteAheadLoggingEnabled(true)
            val db = helper.writableDatabase

            db.query("vault", null, "id = 1", null, null, null, null).use { cursor ->
                if (!cursor.moveToFirst()) {
                    db.close()
                    return null
                }
                val column = cursor.getColumnIndex("device_key")
                val wrapped = if (column >= 0 && !cursor.isNull(column)) cursor.getBlob(column) else null
                if (wrapped == null) {
                    db.close()
                    return null
                }
                val dek = DeviceKey.unwrap(wrapped)
                if (dek == null) {
                    db.close()
                    return null
                }
                return LocalStore(db, dek)
            }
        }

        /** Stores a device wrapping of the data key, if the device can hold one. */
        private fun rememberDeviceKey(db: SQLiteDatabase, dek: ByteArray) {
            val wrapped = DeviceKey.wrap(dek) ?: return
            runCatching {
                db.execSQL("UPDATE vault SET device_key = ? WHERE id = 1", arrayOf<Any>(wrapped))
            }
        }

        /** True when this device can open its vault without being asked. */
        fun hasDeviceKey(context: Context, name: String): Boolean {
            if (!context.getDatabasePath(name).exists()) return false
            return runCatching {
                val helper = OpenHelper(context.applicationContext, name)
                helper.readableDatabase.use { db ->
                    db.query("vault", null, "id = 1", null, null, null, null).use { cursor ->
                        if (!cursor.moveToFirst()) return false
                        val column = cursor.getColumnIndex("device_key")
                        column >= 0 && !cursor.isNull(column)
                    }
                }
            }.getOrDefault(false)
        }

        /**
         * Removes the device wrapping, leaving the vault itself untouched.
         *
         * Only the `device_key` column is nulled. The data key is still there,
         * still wrapped under the scrypt-derived key from the passphrase, and
         * every row of every table is exactly as it was — so this costs the
         * user nothing except being asked for their passphrase again. That is
         * the whole point: somebody who is about to hand their phone over wants
         * the app to stop opening itself, not to lose their account.
         *
         * Deleting the keystore entry is the other half and belongs to
         * [DeviceKey]; either half alone would leave the shortcut dead, and
         * doing both means nothing is left on this device that could rebuild
         * it. Called on a device that has no vault, or a vault that never had a
         * wrapping, this does nothing and reports success, because both are
         * already the state it is trying to produce.
         */
        fun clearDeviceKey(context: Context, name: String) {
            if (!context.getDatabasePath(name).exists()) return
            runCatching {
                val helper = OpenHelper(context.applicationContext, name)
                helper.writableDatabase.use { db ->
                    db.execSQL("UPDATE vault SET device_key = NULL WHERE id = 1")
                }
            }
        }

        /**
         * Opens an existing vault or creates one. The data-encryption key is
         * random and never derived from the passphrase directly, so a passphrase
         * change rewraps one key rather than re-encrypting the whole database.
         */
        fun open(context: Context, name: String, passphrase: String): LocalStore {
            val helper = OpenHelper(context.applicationContext, name)
            // Enabled on the helper, outside any transaction. WAL keeps a reader
            // from blocking the writer, which matters because the delivery
            // worker writes while the UI reads.
            helper.setWriteAheadLoggingEnabled(true)
            val db = helper.writableDatabase

            db.query("vault", null, "id = 1", null, null, null, null).use { cursor ->
                if (cursor.moveToFirst()) {
                    val salt = cursor.getBlob(cursor.getColumnIndexOrThrow("kdf_salt"))
                    val wrapped = cursor.getBlob(cursor.getColumnIndexOrThrow("wrapped_key"))
                    val params = Vault.KdfParameters(
                        n = cursor.getInt(cursor.getColumnIndexOrThrow("kdf_n")),
                        r = cursor.getInt(cursor.getColumnIndexOrThrow("kdf_r")),
                        p = cursor.getInt(cursor.getColumnIndexOrThrow("kdf_p")),
                    )
                    val kek = Vault.deriveKey(passphrase, salt, params)
                    val dek = try {
                        Vault.open(kek, Vault.aad("vault", "dek"), wrapped)
                    } catch (t: Throwable) {
                        db.close()
                        throw IllegalStateException(
                            "wrong passphrase, or the local database has been tampered with",
                            t,
                        )
                    } finally {
                        // The passphrase-derived key has done its one job. Zeroed
                        // on every path, including the wrong-passphrase one, which
                        // still derived a key and still left it in memory.
                        kek.fill(0)
                    }
                    // Record a device wrapping so the next launch need not ask.
                    // Done here rather than at registration as well, so an
                    // account made before this existed picks one up simply by
                    // being opened.
                    rememberDeviceKey(db, dek)
                    return LocalStore(db, dek)
                }
            }

            val salt = Vault.randomSalt()
            val params = Vault.KdfParameters()
            val kek = Vault.deriveKey(passphrase, salt, params)
            val dek = Vault.randomDataKey()
            val wrapped = Vault.seal(kek, Vault.aad("vault", "dek"), dek)
            kek.fill(0)

            db.execSQL(
                "INSERT INTO vault (id, kdf_salt, wrapped_key, kdf_n, kdf_r, kdf_p) VALUES (1, ?, ?, ?, ?, ?)",
                arrayOf<Any>(salt, wrapped, params.n, params.r, params.p),
            )
            rememberDeviceKey(db, dek)
            return LocalStore(db, dek)
        }
    }

    private class OpenHelper(context: Context, name: String) :
        SQLiteOpenHelper(context, name, null, SCHEMA_VERSION) {

        /**
         * Both settings belong here rather than in onCreate.
         *
         * onCreate runs inside a transaction, and `PRAGMA journal_mode = WAL`
         * cannot be executed inside one — it throws, so the vault could never
         * be created at all. onConfigure runs before any transaction is open,
         * and the framework's own setters are the supported way to reach both
         * pragmas on Android.
         */
        override fun onConfigure(db: SQLiteDatabase) {
            db.setForeignKeyConstraintsEnabled(true)
        }

        override fun onCreate(db: SQLiteDatabase) {
            for (statement in SCHEMA) db.execSQL(statement)
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            // Additive only, and nullable: an existing vault keeps its data key
            // and its passphrase wrapping untouched. The device wrapping is
            // filled in the next time the passphrase opens it, so an upgrade
            // never has to re-derive anything and never risks the account.
            if (oldVersion < 2) {
                db.execSQL("ALTER TABLE vault ADD COLUMN device_key BLOB")
            }
        }
    }
}

private val SCHEMA: List<String> = listOf(
    """
    CREATE TABLE IF NOT EXISTS vault (
        id           INTEGER PRIMARY KEY CHECK (id = 1),
        kdf_salt     BLOB NOT NULL,
        wrapped_key  BLOB NOT NULL,
        kdf_n        INTEGER NOT NULL,
        kdf_r        INTEGER NOT NULL,
        kdf_p        INTEGER NOT NULL,
        device_key   BLOB
    )
    """.trimIndent(),
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sessions (address TEXT PRIMARY KEY, record BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS identities (address TEXT PRIMARY KEY, key BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS signed_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS kyber_prekeys (
        id      INTEGER PRIMARY KEY,
        record  BLOB NOT NULL,
        used    INTEGER NOT NULL DEFAULT 0
    )
    """.trimIndent(),
)
