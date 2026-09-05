package uz.millygram.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.PlatformImeOptions
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * First run, and unlock.
 *
 * The two states share a screen because they ask for overlapping things and
 * differ mainly in whether a username is still available to choose. Both say
 * plainly what the passphrase is for: it is the only thing standing between
 * someone holding the handset and the conversations on it, and a person who
 * does not know that will pick something short.
 */
@Composable
fun OnboardingScreen(
    creating: Boolean,
    busy: String?,
    error: String?,
    defaultServer: String,
    defaultRelay: String,
    onRegister: (username: String, passphrase: String, server: String, relay: String) -> Unit,
    onUnlock: (passphrase: String, server: String, relay: String) -> Unit,
    onDismissError: () -> Unit,
) {
    var username by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var server by remember { mutableStateOf(defaultServer) }
    var relay by remember { mutableStateOf(defaultRelay) }
    var showServer by remember { mutableStateOf(false) }

    Column(
        Modifier
            .fillMaxSize()
            .background(theme.background)
            .statusBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = Space.gutter),
    ) {
        Spacer(Modifier.height(64.dp))

        Text(
            if (creating) "MillyGram" else "Qulfni oching",
            style = MillyType.LargeTitle,
            color = theme.textPrimary,
        )
        Spacer(Modifier.height(Space.sm))
        Text(
            if (creating) {
                "Telefon raqami kerak emas. Faqat oʻzingizga nom tanlang."
            } else {
                "Suhbatlaringiz shu parol bilan shifrlangan."
            },
            style = MillyType.Notice,
            color = theme.textSecondary,
        )

        Spacer(Modifier.height(Space.xxl))

        if (creating) {
            FieldLabel("Foydalanuvchi nomi")
            Field(
                value = username,
                placeholder = "masalan, dilnoza_az",
                prefix = "@",
                onValueChange = {
                    // ASCII only by protocol rule: a lookalike handle would let
                    // one person be mistaken for another.
                    username = it.lowercase().filter { c -> c.isLetterOrDigit() || c == '_' }.take(32)
                },
            )
            Spacer(Modifier.height(Space.lg))
        }

        FieldLabel("Parol")
        Field(
            value = passphrase,
            placeholder = "kamida 8 ta belgi",
            secret = true,
            onValueChange = { passphrase = it },
        )
        Spacer(Modifier.height(Space.sm))
        Text(
            "Bu parol qurilmadagi maʼlumotlarni ochadi. Uni tiklab boʻlmaydi — " +
                "unutsangiz, suhbatlar ham yoʻqoladi.",
            style = MillyType.Timestamp,
            color = theme.textTertiary,
        )

        Spacer(Modifier.height(Space.lg))

        Text(
            if (showServer) "Serverni yashirish" else "Server manzili",
            style = MillyType.Meta,
            color = theme.accent,
            modifier = Modifier.clickable { showServer = !showServer },
        )
        if (showServer) {
            Spacer(Modifier.height(Space.sm))
            FieldLabel("Server")
            Field(value = server, placeholder = "http://…", onValueChange = { server = it })
            Spacer(Modifier.height(Space.md))
            FieldLabel("Yuborish relesi")
            Field(value = relay, placeholder = "http://… (ixtiyoriy)", onValueChange = { relay = it })
            Spacer(Modifier.height(Space.sm))
            Text(
                "Rele xabarni ocholmaydi — u faqat serverga uzatadi. Shu sababli " +
                    "server sizning IP manzilingizni koʻrmaydi. Boʻsh qoldirsangiz, " +
                    "xabarlar toʻgʻridan-toʻgʻri serverga boradi.",
                style = MillyType.Timestamp,
                color = theme.textTertiary,
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

        val ready = passphrase.isNotBlank() && (!creating || username.length >= 3) && busy == null
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(if (ready) theme.accent else theme.field)
                .clickable(enabled = ready) {
                    if (creating) {
                        onRegister(username, passphrase, server, relay)
                    } else {
                        onUnlock(passphrase, server, relay)
                    }
                }
                .padding(vertical = 15.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                busy ?: if (creating) "Hisob yaratish" else "Ochish",
                style = MillyType.Label,
                color = if (ready) theme.onAccent else theme.textTertiary,
            )
        }

        Spacer(Modifier.height(Space.xxl))
        Box(Modifier.fillMaxWidth().navigationBarsPadding(), contentAlignment = Alignment.Center) {
            Text(
                "Uchidan-uchigacha shifrlangan · Ochiq kodli",
                style = MillyType.Timestamp,
                color = theme.textTertiary,
                textAlign = TextAlign.Center,
            )
        }
        Spacer(Modifier.height(Space.xl))
    }
}

@Composable
private fun FieldLabel(text: String) {
    Text(text, style = MillyType.SectionHeader, color = theme.textTertiary)
    Spacer(Modifier.height(Space.sm))
}

@Composable
private fun Field(
    value: String,
    placeholder: String,
    onValueChange: (String) -> Unit,
    prefix: String? = null,
    secret: Boolean = false,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(2.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(Radius.field))
            .background(theme.field)
            .height(50.dp)
            .padding(horizontal = 15.dp),
    ) {
        if (prefix != null) {
            Text(prefix, style = MillyType.Label, color = theme.textTertiary)
            Spacer(Modifier.width(2.dp))
        }
        Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
            if (value.isEmpty()) {
                Text(placeholder, style = MillyType.Preview, color = theme.textTertiary)
            }
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                singleLine = true,
                visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
                keyboardOptions = KeyboardOptions(
                    autoCorrectEnabled = false,
                    // A passphrase field is the one place the platform's own
                    // no-learning flag is reachable, because Compose sets it for
                    // password input types.
                    keyboardType = if (secret) KeyboardType.Password else KeyboardType.Ascii,
                    platformImeOptions = PlatformImeOptions("noPersonalizedLearning"),
                ),
                textStyle = LocalTextStyle.current.merge(MillyType.Body).merge(
                    TextStyle(color = theme.textPrimary),
                ),
                cursorBrush = SolidColor(theme.accent),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
