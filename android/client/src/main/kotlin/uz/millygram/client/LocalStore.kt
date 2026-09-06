package uz.millygram.client

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.Closeable
import org.json.JSONArray
import org.json.JSONObject
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
        for (table in ALLOWED_TABLES) {
            val idColumn = idColumnFor(table)
            val valueColumn = valueColumnFor(table)
            db.query(table, arrayOf(idColumn, valueColumn), null, null, null, null, null).use { cursor ->
                while (cursor.moveToNext()) {
                    rows.put(
                        JSONObject().apply {
                            put("table", table)
                            put("id", cursor.getString(0))
                            put("value", android.util.Base64.encodeToString(cursor.getBlob(1), BASE64))
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
        }.toString().toByteArray(Charsets.UTF_8)
    }

    companion object {
        private const val SCHEMA_VERSION = 1
        private const val BACKUP_FORMAT = "millygram-backup-v1"
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
            require(parsed.optString("format") == BACKUP_FORMAT) { "not a MillyGram backup" }

            val salt = android.util.Base64.decode(parsed.getString("salt"), BASE64)
            val wrapped = android.util.Base64.decode(parsed.getString("wrappedKey"), BASE64)
            val params = Vault.KdfParameters(
                n = parsed.getInt("kdfN"),
                r = parsed.getInt("kdfR"),
                p = parsed.getInt("kdfP"),
            )

            // Checked before anything is written, so a wrong passphrase costs
            // nothing but the derivation.
            val kek = Vault.deriveKey(passphrase, salt, params)
            try {
                Vault.open(kek, Vault.aad("vault", "dek"), wrapped)
            } catch (t: Throwable) {
                throw IllegalStateException("wrong passphrase for this backup", t)
            } finally {
                kek.fill(0)
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
                val rows = parsed.getJSONArray("rows")
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
            // There is only one schema version so far. A future upgrade should
            // migrate in place under the same key, never re-derive it.
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
        kdf_p        INTEGER NOT NULL
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
