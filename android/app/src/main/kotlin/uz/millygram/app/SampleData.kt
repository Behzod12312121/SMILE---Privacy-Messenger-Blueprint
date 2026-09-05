package uz.millygram.app

import uz.millygram.app.ui.Account
import uz.millygram.app.ui.Contact
import uz.millygram.app.ui.Conversation
import uz.millygram.app.ui.Message
import uz.millygram.app.ui.ReplyContext
import uz.millygram.app.ui.TimelineItem

/**
 * Content for laying the interface out before it is wired to a live account.
 *
 * The text is deliberately real Uzbek rather than lorem ipsum, and it exercises
 * the three scripts a user in Tashkent actually switches between mid-thread:
 * Uzbek Latin, Uzbek Cyrillic and Russian. It also carries both modifier
 * letters the language needs — U+02BB in `Toʻrayev` and `koʻring`, U+02BC in
 * `Aʼzamova` and `maʼlumot` — which is the fastest way to catch a font or an
 * input path that flattens them into a straight quote.
 */
object SampleData {

    val conversations = listOf(
        Conversation(
            aci = "4aecbadd-bec0-4e2f-8f5d-71e0ace76688",
            displayName = "Dilnoza Aʼzamova",
            username = "dilnoza_az",
            preview = "Maʼlumotlarni yubordim, tekshirib koʻring",
            timestamp = "14:32",
            unread = 2,
        ),
        Conversation(
            aci = "c2cab6a9-e36a-4f2a-bd17-6feb10f0da90",
            displayName = "Gʻayrat Toʻrayev",
            username = "gayrat",
            preview = "Kelishdik, ertaga koʻrishamiz",
            timestamp = "14:05",
        ),
        Conversation(
            aci = "90ce12e4-2da3-4998-a924-1b948ae1ff42",
            displayName = "Oila",
            username = "oila",
            preview = "Kechqurun kelasizmi?",
            previewPrefix = "Nodira",
            timestamp = "13:22",
            unread = 5,
        ),
        Conversation(
            aci = "bf22f26b-9873-4ff0-ab30-d4309e0525d0",
            displayName = "Toshkent jamoasi",
            username = "toshkent",
            preview = "Hisobot tayyor, koʻrib chiqing",
            previewPrefix = "Feruza",
            timestamp = "11:48",
        ),
        Conversation(
            aci = "5d2f22a8-c814-4c70-b961-5a505dc569f1",
            displayName = "Санжар Каримов",
            username = "sanjar_k",
            preview = "Хорошо, договорились",
            timestamp = "10:31",
        ),
        Conversation(
            aci = "03657a56-0939-45c8-bc40-4939d3c64328",
            displayName = "Oʻktam Sobirov",
            username = "oktam",
            preview = "Rahmat! Oʻqib chiqaman",
            timestamp = "Juma",
            outgoing = true,
        ),
        Conversation(
            aci = "69402b5c-bdf6-4725-bff5-7c20cb2bfaa1",
            displayName = "Feruza Yoʻldosheva",
            username = "feruza",
            preview = "Hujjat qabul qilindi",
            timestamp = "Payshanba",
        ),
        Conversation(
            aci = "24fd7fec-f941-4705-961d-e9d338e37421",
            displayName = "Nodira Karimova",
            username = "nodira",
            preview = "Кечқурун телефон қиламан",
            timestamp = "28.08",
        ),
    )

    val timeline = listOf(
        TimelineItem.EncryptionNotice,
        TimelineItem.DayDivider("Bugun"),
        TimelineItem.Bubble(
            Message(1, "Salom! Ertaga soat 10 da uchrashamizmi?", "09:41", outgoing = false),
        ),
        TimelineItem.Bubble(
            Message(2, "Ha, aynan shu vaqtda boʻladi.", "09:43", outgoing = true),
        ),
        TimelineItem.Bubble(
            Message(3, "Zoʻr. Maʼlumotlarni oldindan yuboraman.", "09:44", outgoing = false),
        ),
        TimelineItem.Bubble(
            Message(
                id = 4,
                body = "Rahmat, oʻqib chiqaman.",
                timestamp = "09:46",
                outgoing = true,
                replyTo = ReplyContext("Gʻayrat Toʻrayev", "Maʼlumotlarni oldindan yuboraman."),
            ),
        ),
        TimelineItem.Bubble(
            Message(5, "Кечқурун телефон қиламан", "09:52", outgoing = false),
        ),
        TimelineItem.Bubble(
            Message(6, "Albatta, kutaman.", "09:53", outgoing = true, delivered = false),
        ),
    )

    val recents = listOf(
        Contact("c2cab6a9-e36a-4f2a-bd17-6feb10f0da90", "Gʻayrat Toʻrayev", "gayrat"),
        Contact("4aecbadd-bec0-4e2f-8f5d-71e0ace76688", "Dilnoza Aʼzamova", "dilnoza_az"),
        Contact("03657a56-0939-45c8-bc40-4939d3c64328", "Oʻktam Sobirov", "oktam"),
        Contact("5d2f22a8-c814-4c70-b961-5a505dc569f1", "Санжар Каримов", "sanjar_k"),
    )

    val account = Account(
        displayName = "Bekzod Rahimov",
        username = "bekzod",
        // Sixty digits, the shape libsignal's numeric fingerprint actually produces.
        safetyNumber = "136668194090538129489159998885426577101206919653087703146078",
        deviceCount = 2,
        keyTransparencyVerified = true,
        readReceipts = false,
        screenLock = true,
        language = "Oʻzbekcha (lotin)",
        theme = "Tizim",
        buildHash = "a91fc2",
    )
}
