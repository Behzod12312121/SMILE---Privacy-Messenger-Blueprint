package uz.millygram.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material3.Icon
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
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * Writing the account out to a file the user keeps.
 *
 * The screen spends most of its space saying what the file is, because the
 * honest description of it is uncomfortable: it is the account. Anyone holding
 * it and its passphrase can be this person to every one of their contacts, and
 * none of those contacts would see anything change — the safety numbers stay
 * the same, which is exactly what makes a restore work and exactly what makes a
 * stolen backup invisible.
 *
 * That is why nothing here happens automatically and nothing is uploaded
 * anywhere. Somebody who would rather carry the risk of losing the phone than
 * the risk of a copy existing simply never opens this screen.
 */
@Composable
fun BackupScreen(
    onBack: () -> Unit,
    onSave: (passphrase: String) -> Unit,
    busy: Boolean = false,
    error: String? = null,
) {
    var passphrase by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }

    val matched = passphrase.length >= 8 && passphrase == again
    Column(
        Modifier
            .fillMaxSize()
            .background(theme.background)
            .statusBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState()),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 6.dp).height(Space.minTouchTarget),
        ) {
            Box(
                Modifier.size(Space.minTouchTarget).clickable(onClick = onBack),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.ArrowBack, "Orqaga", tint = theme.accent, modifier = Modifier.size(24.dp))
            }
        }

        Column(Modifier.padding(horizontal = Space.gutter)) {
            Text("Zaxira nusxa", style = MillyType.LargeTitle, color = theme.textPrimary)
            Spacer(Modifier.height(Space.lg))
            Text(
                "Bu fayl — hisobingizning oʻzi. Uni va parolini bilgan odam siz " +
                    "boʻlib yozisha oladi, va suhbatdoshlaringiz buni sezmaydi: " +
                    "xavfsizlik raqamlari oʻzgarmaydi.",
                style = MillyType.Notice,
                color = theme.textSecondary,
            )
            Spacer(Modifier.height(Space.md))
            Text(
                "Shu sababli u hech qayerga yuborilmaydi. Faylni qayerda " +
                    "saqlashni oʻzingiz hal qilasiz. Telefonni yoʻqotish " +
                    "xavfidan koʻra nusxaning mavjudligi xavfli deb bilsangiz, " +
                    "bu sahifani ochmang.",
                style = MillyType.Notice,
                color = theme.textSecondary,
            )

            Spacer(Modifier.height(Space.xl))
            Text("Zaxira paroli", style = MillyType.SectionHeader, color = theme.textTertiary)
            Spacer(Modifier.height(Space.sm))
            Secret(passphrase, "kamida 8 ta belgi") { passphrase = it }
            Spacer(Modifier.height(Space.md))
            Secret(again, "parolni takrorlang") { again = it }

            if (error != null) {
                Spacer(Modifier.height(Space.lg))
                Text(error, style = MillyType.Notice, color = theme.danger)
            }

            Spacer(Modifier.height(Space.xl))
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(if (matched && !busy) theme.accent else theme.field)
                    .clickable(enabled = matched && !busy) { onSave(passphrase) }
                    .padding(vertical = 15.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (busy) "Saqlanmoqda…" else "Faylga saqlash",
                    style = MillyType.Label,
                    color = if (matched && !busy) theme.onAccent else theme.textTertiary,
                )
            }
            Spacer(Modifier.height(Space.xxl))
            Spacer(Modifier.navigationBarsPadding())
        }
    }
}

@Composable
private fun Secret(value: String, placeholder: String, onValueChange: (String) -> Unit) {
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(Radius.field))
            .background(theme.field)
            .height(50.dp)
            .padding(horizontal = 15.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        if (value.isEmpty()) {
            Text(placeholder, style = MillyType.Preview, color = theme.textTertiary)
        }
        BasicTextField(
            value = value,
            onValueChange = { if (it.length <= 256) onValueChange(it) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Password,
                platformImeOptions = PlatformImeOptions("noPersonalizedLearning"),
            ),
            textStyle = MillyType.Body.merge(TextStyle(color = theme.textPrimary)),
            cursorBrush = SolidColor(theme.accent),
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
