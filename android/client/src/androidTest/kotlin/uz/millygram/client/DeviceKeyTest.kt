package uz.millygram.client

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Opening the vault without a passphrase.
 *
 * The passphrase every launch is what made this app feel like work next to the
 * messengers people already use. The data key is wrapped a second time by a key
 * the device holds and cannot export, so a normal launch asks for nothing and a
 * copied database is still worth nothing elsewhere.
 */
@RunWith(AndroidJUnit4::class)
class DeviceKeyTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * The device key needs a screen lock to exist at all, so on a device
     * without one there is nothing here to test — and falling back to the
     * passphrase is the correct behaviour rather than a failure.
     */
    @Before
    fun requireAScreenLock() {
        val keyguard = context.getSystemService(android.app.KeyguardManager::class.java)
        Assume.assumeTrue(
            "no secure lock screen on this device, so no device key can exist",
            keyguard?.isDeviceSecure == true,
        )
    }

    @Test
    fun aVaultOpenedWithAPassphraseCanBeReopenedWithoutOne() {
        val name = "devicekey-${UUID.randomUUID().toString().take(8)}.db"
        val passphrase = "a passphrase for the device key test"

        // Creating it should record the device wrapping straight away.
        LocalStore.open(context, name, passphrase).use { store ->
            store.setMetaString("probe", "hello")
        }

        assertTrue(
            "a device with a screen lock should be able to hold the key",
            LocalStore.hasDeviceKey(context, name),
        )

        val reopened = LocalStore.openWithDeviceKey(context, name)
        assertNotNull("the vault must open without the passphrase", reopened)
        reopened!!.use { store ->
            assertEquals("hello", store.getMetaString("probe"))
        }

        // And the passphrase must still work, since that is what backups and a
        // removed screen lock fall back to.
        LocalStore.open(context, name, passphrase).use { store ->
            assertEquals("hello", store.getMetaString("probe"))
        }
    }

    @Test
    fun theDeviceKeyIsUnusableOnceForgotten() {
        val name = "forgotten-${UUID.randomUUID().toString().take(8)}.db"
        LocalStore.open(context, name, "another passphrase entirely").use { it.setMetaString("probe", "x") }

        DeviceKey.forget()

        // The wrapping is still in the row, but nothing can open it, so the
        // caller has to ask. Losing the key must never lose the account.
        assertEquals(null, LocalStore.openWithDeviceKey(context, name))
        LocalStore.open(context, name, "another passphrase entirely").use {
            assertEquals("x", it.getMetaString("probe"))
        }
    }
}
