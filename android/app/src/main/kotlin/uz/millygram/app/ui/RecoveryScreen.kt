package uz.millygram.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * Taking a handle back on a new handset.
 *
 * Two steps in one screen, because they are one thought: the number, then the
 * code that arrives at it. What the screen has to be honest about is that this
 * is not the old account coming back. The gateway never held the private key,
 * so what returns is the name — no conversations, and a safety number that
 * every contact will see change. People arrive here having lost a phone and
 * will read "tiklash" as "restore"; the text says otherwise before they commit,
 * not after.
 */
@Composable
fun RecoveryScreen(
    codeSent: Boolean,
    phoneNumber: String,
    busy: String?,
    error: String?,
    onSendCode: (phoneNumber: String) -> Unit,
    onRecover: (code: String, passphrase: String) -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
) {
    var number by remember { mutableStateOf(phoneNumber.ifEmpty { "+998" }) }
    var code by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }

    Column(
        Modifier
            .fillMaxSize()
            .background(theme.background)
            .statusBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = Space.gutter),
    ) {
        Spacer(Modifier.height(Space.xl))
        Text(
            "Orqaga",
            style = MillyType.Meta,
            color = theme.accent,
            modifier = Modifier.clickable(onClick = onBack),
        )

        Spacer(Modifier.height(Space.xxl))
        Text("Hisobni tiklash", style = MillyType.LargeTitle, color = theme.textPrimary)
        Spacer(Modifier.height(Space.sm))
        Text(
            if (codeSent) {
                "Kod $phoneNumber raqamiga yuborildi."
            } else {
                "Hisobingizga ulangan telefon raqamini kiriting."
            },
            style = MillyType.Notice,
            color = theme.textSecondary,
        )

        Spacer(Modifier.height(Space.xl))

        if (!codeSent) {
            FieldLabel("Telefon raqami")
            Field(
                value = number,
                placeholder = "+998901234567",
                onValueChange = { candidate ->
                    // The gateway wants E.164 and nothing else. Filtering here
                    // means a number copied out of a contacts app with spaces
                    // or brackets in it is accepted rather than rejected on a
                    // technicality the user cannot see.
                    number = candidate.filter { it.isDigit() || it == '+' }
                },
            )
        } else {
            FieldLabel("Kod")
            Field(
                value = code,
                placeholder = "6 xonali kod",
                onValueChange = { candidate -> code = candidate.filter(Char::isDigit).take(6) },
            )
            Spacer(Modifier.height(Space.lg))
            FieldLabel("Yangi parol")
            Field(
                value = passphrase,
                placeholder = "kamida 8 ta belgi",
                secret = true,
                onValueChange = { passphrase = it },
            )
            Spacer(Modifier.height(Space.sm))
            Text(
                "Bu yangi qurilmadagi maʼlumotlarni ochadigan parol.",
                style = MillyType.Timestamp,
                color = theme.textTertiary,
            )
        }

        Spacer(Modifier.height(Space.lg))
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(Radius.card))
                .background(theme.noticeSurface)
                .padding(Space.lg),
        ) {
            Text(
                "Eski suhbatlar qaytmaydi — ular faqat yoʻqolgan telefonda edi. " +
                    "Nomingiz qaytadi, kalitlaringiz esa yangi boʻladi, shuning uchun " +
                    "suhbatdoshlaringiz xavfsizlik raqami oʻzgarganini koʻradi.",
                style = MillyType.Timestamp,
                color = theme.noticeStrong,
            )
        }

        if (error != null) {
            Spacer(Modifier.height(Space.lg))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(Radius.card))
                    .background(theme.noticeSurface)
                    .clickable(onClick = onDismissError)
                    .padding(Space.lg),
            ) {
                Text(error, style = MillyType.Notice, color = theme.noticeStrong)
            }
        }

        Spacer(Modifier.height(Space.xl))

        val ready = busy == null && if (codeSent) {
            code.length == 6 && passphrase.isNotBlank()
        } else {
            number.length > 8
        }
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(if (ready) theme.accent else theme.field)
                .clickable(enabled = ready) {
                    if (codeSent) onRecover(code, passphrase) else onSendCode(number)
                }
                .padding(vertical = 15.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                busy ?: if (codeSent) "Hisobni tiklash" else "Kod yuborish",
                style = MillyType.Label,
                color = if (ready) theme.onAccent else theme.textTertiary,
            )
        }

        Spacer(Modifier.height(Space.xxl))
        Spacer(Modifier.navigationBarsPadding())
    }
}
