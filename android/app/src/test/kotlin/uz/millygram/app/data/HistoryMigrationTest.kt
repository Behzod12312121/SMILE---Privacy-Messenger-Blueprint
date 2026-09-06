package uz.millygram.app.data

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject

/**
 * History used to live in one blob holding every conversation, rewritten in
 * full whenever anything changed. Splitting it per conversation is the fix; not
 * losing anybody's messages on the way is the part that has to be right, and
 * the only people it affects are those who already have history.
 */
class HistoryMigrationTest {

    private fun legacy(vararg conversations: Pair<String, List<String>>): String {
        val array = JSONArray()
        for ((aci, bodies) in conversations) {
            array.put(
                JSONObject().apply {
                    put("aci", aci)
                    put("username", "user_$aci")
                    put(
                        "messages",
                        JSONArray().apply {
                            bodies.forEach { body ->
                                put(
                                    JSONObject().apply {
                                        put("body", body)
                                        put("sentAt", 1788000000000L)
                                        put("outgoing", true)
                                        put("delivery", "sent")
                                    },
                                )
                            }
                        },
                    )
                },
            )
        }
        return array.toString()
    }

    @Test
    fun `every conversation survives the split, with its messages`() {
        val blob = legacy(
            "aaaa-1" to listOf("salom", "qalaysiz"),
            "bbbb-2" to listOf("yaxshi"),
        )

        val split = splitLegacyHistory(blob)

        assertEquals("""["aaaa-1","bbbb-2"]""", split.index)
        assertEquals(2, split.conversations.size)

        val first = JSONObject(split.conversations[0].second)
        assertEquals("user_aaaa-1", first.getString("username"))
        assertEquals(2, first.getJSONArray("messages").length())
        assertEquals("salom", first.getJSONArray("messages").getJSONObject(0).getString("body"))

        val second = JSONObject(split.conversations[1].second)
        assertEquals("yaxshi", second.getJSONArray("messages").getJSONObject(0).getString("body"))
    }

    @Test
    fun `an empty history splits into nothing rather than failing`() {
        val split = splitLegacyHistory("[]")
        assertEquals("[]", split.index)
        assertTrue(split.conversations.isEmpty())
    }

    @Test
    fun `delivery state carries across, so a failed message stays failed`() {
        val split = splitLegacyHistory(legacy("aaaa-1" to listOf("bitta")))
        val messages = JSONObject(split.conversations[0].second).getJSONArray("messages")
        assertEquals("sent", messages.getJSONObject(0).getString("delivery"))
    }
}
