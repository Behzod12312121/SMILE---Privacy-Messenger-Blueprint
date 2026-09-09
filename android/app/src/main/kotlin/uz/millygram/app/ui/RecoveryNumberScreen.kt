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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * Attaching, or removing, the number an account can be taken back with.
 *
 * The whole screen is one decision and it deserves the space, because it is the
 * only place in this app where a user hands the gateway something that points
 * back at them. A SIM here is registered against a passport. So the text names
 * the cost in the concrete — a gateway that can answer "which account has this
 * number" — instead of the usual soft phrasing about improving your experience,
 * and the default stays off.
 *
 * Nothing verifies the number here, deliberately: sending a code at signup is
 * the friction this feature exists to avoid. The price is that a typo is not
 * discovered until recovery, when it is far too late, so the warning says so in
 * those words rather than in the language of an advisory.
 */
@Composable
fun RecoveryNumberScreen(
    current: String?,
    busy: Boolean,
    error: String?,
    onAttach: (String) -> Unit,
    onDetach: () -> Unit,
    onBack: () -> Unit,
) {
    var number by remember { mutableStateOf(current ?: "+998") }
    // One tap between typing a number and living with it. The number is already
    // on screen in the field above, so this is not there to show it again — it
    // is there to make the last action deliberate, because nothing after this
    // point ever checks the number until the day it has to work.
    var confirming by remember { mutableStateOf(false) }

    Column(
        Modifier
            .fillMaxSize()
            .background(theme.surface)
            .statusBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState()),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 6.dp).padding(top = Space.xs),
        ) {
            Box(
                Modifier.size(Space.minTouchTarget).clickable(onClick = onBack),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.ArrowBack, "Orqaga", tint = theme.accent, modifier = Modifier.size(24.dp))
            }
        }

        Column(Modifier.padding(horizontal = Space.gutter)) {
            Text("Tiklash raqami", style = MillyType.LargeTitle, color = theme.textPrimary)
            Spacer(Modifier.height(Space.sm))
            Text(
                "Telefoningizni yoʻqotsangiz, shu raqam orqali nomingizni qaytarib " +
                    "olasiz. Roʻyxatdan oʻtishda raqam soʻralmaydi — bu ixtiyoriy.",
                style = MillyType.Notice,
                color = theme.textSecondary,
            )

            Spacer(Modifier.height(Space.xl))
            FieldLabel("Telefon raqami")
            Field(
                value = number,
                placeholder = "+998901234567",
                onValueChange = { candidate ->
                    number = candidate.filter { it.isDigit() || it == '+' }
                },
            )

            Spacer(Modifier.height(Space.lg))
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(Radius.card))
                    .background(theme.noticeSurface)
                    .padding(Space.lg),
            ) {
                Column {
                    Text(
                        "Nimani bilib qoʻying",
                        style = MillyType.Label,
                        color = theme.noticeStrong,
                    )
                    Spacer(Modifier.height(Space.xs))
                    Text(
                        "Raqam hozir tekshirilmaydi. Kod faqat hisobni tiklaganda " +
                            "yuboriladi — shuning uchun raqamni xato yozsangiz, buni " +
                            "telefoningizni yoʻqotgan kuningizgina bilib qolasiz va " +
                            "hisob butunlay yoʻqoladi. Raqamni yuborishdan oldin " +
                            "diqqat bilan tekshiring.\n\n" +
                            "Server raqamingizni xesh koʻrinishida saqlaydi. Bu shuni " +
                            "anglatadiki, raqamingizni biladigan odam sizning Smile’da " +
                            "borligingizni aniqlay oladi, server esa hisobingiz bilan " +
                            "raqam oʻrtasidagi bogʻlanishni biladi.\n\n" +
                            "Suhbatlaringiz baribir shifrlangan — bu bogʻlanish " +
                            "xabarlarni ocholmaydi. Ammo maxfiylik siz uchun eng muhim " +
                            "boʻlsa, raqam ulamang va oʻrniga zaxira faylini saqlang.",
                        style = MillyType.Timestamp,
                        color = theme.noticeStrong,
                    )
                }
            }

            if (error != null) {
                Spacer(Modifier.height(Space.lg))
                Box(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(Radius.card))
                        .background(theme.noticeSurface)
                        .padding(Space.lg),
                ) {
                    Text(error, style = MillyType.Notice, color = theme.noticeStrong)
                }
            }

            Spacer(Modifier.height(Space.xl))
            val ready = !busy && number.length > 8 && number != current

            if (confirming) {
                Text(
                    "Shu raqamga ishonchingiz komilmi?",
                    style = MillyType.Label,
                    color = theme.textPrimary,
                )
                Spacer(Modifier.height(Space.xs))
                Text(number, style = MillyType.LargeTitle, color = theme.textPrimary)
                Spacer(Modifier.height(Space.lg))
            }

            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(if (ready) theme.accent else theme.field)
                    .clickable(enabled = ready) {
                        if (confirming) onAttach(number) else confirming = true
                    }
                    .padding(vertical = 15.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    when {
                        busy -> "Saqlanmoqda…"
                        confirming -> "Ha, shu raqam"
                        current == null -> "Raqamni ulash"
                        else -> "Raqamni oʻzgartirish"
                    },
                    style = MillyType.Label,
                    color = if (ready) theme.onAccent else theme.textTertiary,
                )
            }

            if (confirming && !busy) {
                Spacer(Modifier.height(Space.md))
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Text(
                        "Yoʻq, tahrirlayman",
                        style = MillyType.Meta,
                        color = theme.accent,
                        modifier = Modifier.clickable { confirming = false },
                    )
                }
            }

            if (current != null) {
                Spacer(Modifier.height(Space.lg))
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Text(
                        "Raqamni uzish",
                        style = MillyType.Meta,
                        color = theme.danger,
                        modifier = Modifier.clickable(enabled = !busy, onClick = onDetach),
                    )
                }
            }

            Spacer(Modifier.height(Space.xxl))
            Spacer(Modifier.navigationBarsPadding())
        }
    }
}
