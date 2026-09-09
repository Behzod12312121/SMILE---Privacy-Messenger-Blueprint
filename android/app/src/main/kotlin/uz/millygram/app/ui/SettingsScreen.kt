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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import uz.millygram.client.Handles
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * Settings.
 *
 * Two rows here are doing something unusual on purpose. "Oxirgi faollik" is
 * shown greyed with a fixed value rather than as a toggle, because presence is
 * not collected at all and a switch would imply it could be. And the footer
 * states the build hash, because a reproducible build is only meaningful if a
 * user can see which build they are running.
 */
@Composable
fun SettingsScreen(
    account: Account,
    onBack: () -> Unit,
    onToggleScreenLock: (Boolean) -> Unit,
    onCycleNotificationDetail: () -> Unit = {},
    onLock: () -> Unit = {},
    onBackup: () -> Unit = {},
    onRecoveryNumber: () -> Unit = {},
    onToggleRequireUnlock: (Boolean) -> Unit = {},
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(theme.surface)
            .statusBarsPadding()
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
                Icon(
                    Icons.Rounded.ArrowBack,
                    "Orqaga",
                    tint = theme.accent,
                    modifier = Modifier.size(24.dp),
                )
            }
        }

        Text(
            "Sozlamalar",
            style = MillyType.LargeTitle,
            color = theme.textPrimary,
            modifier = Modifier.padding(horizontal = Space.gutter).padding(top = Space.xs, bottom = 14.dp),
        )

        ProfileCard(account)

        Spacer(Modifier.padding(top = Space.xl))
        SectionHeader("Xavfsizlik")
        Card {
            // A safety number belongs to a pair of people, not to an account,
            // so it is reached from the conversation it describes. A row here
            // could only pick one arbitrarily.
            SettingsRow(
                label = "Xavfsizlik raqami",
                value = "Har suhbatda alohida",
                enabled = false,
                leading = { KeyGlyph(theme.textSecondary) },
            )
            RowSeparator()
            // Where the key that unlocks this device's vault physically lives.
            // Shown, not configurable: it is a fact about the hardware, and a
            // user on a phone without a secure element deserves to know the
            // protection is the platform lock rather than a dedicated chip.
            SettingsRow(
                label = "Kalit himoyasi",
                value = when {
                    account.strongBox -> "Alohida xavfsizlik chipi"
                    account.strongBoxHardware -> "Qurilma himoyasi (chip mavjud)"
                    else -> "Qurilma himoyasi (TEE)"
                },
                enabled = false,
                leading = { LockGlyph(theme.textSecondary, size = 20.dp) },
            )
            if (account.environment != "clean") {
                RowSeparator()
                // Only ever shown when something looks wrong, and only ever as a
                // warning to the user — never as a lock. The checks behind it are
                // defeatable, so a determined attacker sees "clean" here anyway;
                // this is for the ordinary user whose phone has quietly been
                // rooted by something they installed.
                SettingsRow(
                    label = "Diqqat: qurilma xavfsizligi",
                    value = "Oʻzgartirilgan muhit aniqlandi",
                    enabled = false,
                    leading = { LockGlyph(theme.danger, size = 20.dp) },
                )
            }
            RowSeparator()
            // Not a chevron. An account is one device by design — there is no
            // linked-device protocol to show a list of, and a row that opened
            // an empty screen would imply there is.
            SettingsRow(
                label = "Faol qurilmalar",
                value = "Bitta (shu qurilma)",
                enabled = false,
                leading = { DeviceGlyph(theme.textSecondary) },
            )
        }

        Spacer(Modifier.padding(top = Space.xl))
        SectionHeader("Bildirishnomalar")
        Card {
            // Cycled rather than opened as a dialog: three options, and the
            // current one is the label.
            SettingsRow(
                label = "Bildirishnomada koʻrsatilsin",
                value = account.notificationDetail,
                leading = { BellGlyph(theme.textSecondary) },
                trailing = { Chevron() },
                onClick = onCycleNotificationDetail,
            )
            RowSeparator()
            // Not a setting. What a locked screen shows is fixed, because the
            // person most likely to read one is standing next to the user.
            SettingsRow(
                label = "Qulflangan ekranda",
                value = "Faqat “Yangi xabar”",
                enabled = false,
                leading = { EyeOffGlyph(theme.textDisabled) },
            )
        }

        Spacer(Modifier.padding(top = Space.xl))
        SectionHeader("Maxfiylik")
        Card {
            // Not a toggle, for the same reason as the row below it: there is
            // no read receipt anywhere in the protocol, so a switch here would
            // control nothing while implying the feature exists and is merely
            // turned off.
            SettingsRow(
                label = "Oʻqilganlik belgisi",
                value = "Yoʻq",
                enabled = false,
                leading = { DeliveryTick(theme.textDisabled, size = 20.dp) },
            )
            RowSeparator()
            // Not a toggle. Presence is never collected, so offering a switch
            // would imply the app could show it if you asked.
            SettingsRow(
                label = "Oxirgi faollik",
                value = "Hech qachon",
                enabled = false,
                leading = { EyeOffGlyph(theme.textDisabled) },
            )
            RowSeparator()
            // Above the screenshot blocker because it is the stronger of the
            // two and the one people come looking for.
            SettingsRow(
                label = "Barmoq izi bilan ochish",
                value = account.unlockUnavailable,
                enabled = account.unlockUnavailable == null,
                leading = { LockGlyph(theme.textSecondary, size = 20.dp) },
                trailing = {
                    if (account.unlockUnavailable == null) {
                        MillyToggle(account.requireUnlock, onToggleRequireUnlock)
                    }
                },
            )
            RowSeparator()
            SettingsRow(
                label = "Ekran qulfi",
                leading = { LockGlyph(theme.textSecondary, size = 20.dp) },
                trailing = { MillyToggle(account.screenLock, onToggleScreenLock) },
            )
        }

        Spacer(Modifier.padding(top = Space.xl))
        SectionHeader("Hisobni yoʻqotmaslik")
        Card {
            // The value doubles as the explanation. "Ulanmagan" is the default
            // and is not a warning: an account with no number attached is the
            // private one, and nagging about it would push people into handing
            // over a number they did not need to.
            SettingsRow(
                label = "Tiklash raqami",
                value = account.recoveryNumber ?: "Ulanmagan",
                leading = { PhoneGlyph(theme.textSecondary) },
                trailing = { Chevron() },
                onClick = onRecoveryNumber,
            )
            // Handles carry digits nobody can guess and there is no directory to
            // search, so being told a name is the only way to be found. This is
            // that, in one paste — and it never touches the gateway, which is
            // why it can be handed over anywhere without the gateway learning
            // that an introduction happened.
            if (Handles.isValidUsername(account.username)) {
                RowSeparator()
                val clipboard = LocalClipboardManager.current
                var copied by remember { mutableStateOf(false) }
                SettingsRow(
                    label = "Taklif havolasi",
                    value = if (copied) "Nusxalandi" else "Nusxalash",
                    leading = { ShieldGlyph(theme.textSecondary) },
                    trailing = { Chevron() },
                    onClick = {
                        clipboard.setText(AnnotatedString(Handles.createLink(account.username)))
                        copied = true
                    },
                )
            }
            RowSeparator()
            SettingsRow(
                label = "Zaxira nusxa",
                value = "Faylga saqlash",
                leading = { KeyGlyph(theme.textSecondary) },
                trailing = { Chevron() },
                onClick = onBackup,
            )
        }

        Spacer(Modifier.padding(top = Space.xl))
        Card {
            // Closing the app does not close the session any more — delivery
            // keeps running so notifications can arrive — so there has to be a
            // way to say stop.
            //
            // The value line is the one thing on this screen that has to be
            // exactly true. This row used to read "Suhbatlarni yopish" while the
            // device kept its own key to the vault, so the next tap on the app
            // icon reopened everything without asking; somebody who pressed it
            // before handing the phone over was told one thing and given
            // another. It now destroys that key as well, and says so, because
            // the whole reason a person reaches for this row is that they are
            // about to be parted from the handset and need to know what the app
            // will do while it is out of their hands.
            SettingsRow(
                label = "Qulflash",
                value = "Parol soʻraladi",
                leading = { KeyGlyph(theme.textSecondary) },
                trailing = { Chevron() },
                onClick = onLock,
            )
            RowSeparator()
            // Not clickable: it is the sentence the row above needs and does not
            // have room for. Delivery stops too, so nothing arrives until the
            // passphrase is typed again — worth stating rather than leaving the
            // user to discover it as silence.
            SettingsRow(
                label = "Suhbatlar yopiladi, xabarlar kelmaydi",
                enabled = false,
                leading = { LockGlyph(theme.textDisabled, size = 20.dp) },
            )
        }

        Spacer(Modifier.padding(top = Space.xl))
        SectionHeader("Koʻrinish")
        Card {
            SettingsRow(
                label = "Mavzu",
                value = account.theme,
                leading = { Icon(Icons.Rounded.DarkMode, null, tint = theme.textSecondary, modifier = Modifier.size(20.dp)) },
                trailing = { Chevron() },
            )
            RowSeparator()
            SettingsRow(
                label = "Til",
                value = account.language,
                leading = { Icon(Icons.Rounded.Language, null, tint = theme.textSecondary, modifier = Modifier.size(20.dp)) },
                trailing = { Chevron() },
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(3.dp),
            modifier = Modifier.fillMaxWidth().padding(top = Space.xxl, bottom = Space.xxl),
        ) {
            Text("Smile 1.0 · Ochiq kodli", style = MillyType.Timestamp, color = theme.textTertiary)
            Text(
                "Qurilish · ${account.buildHash}",
                style = MillyType.Timestamp,
                color = theme.textDisabled,
            )
        }
    }
}

@Composable
private fun ProfileCard(account: Account) {
    Box(Modifier.fillMaxWidth().padding(horizontal = Space.lg)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(Radius.card))
                .background(theme.surfaceRaised)
                .padding(Space.lg),
        ) {
            Avatar(account.avatarSeed, account.displayName, 58.dp, animated = true)
            Spacer(Modifier.width(15.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(account.displayName, style = MillyType.Title, color = theme.textPrimary)
                Text("@${account.username}", style = MillyType.Meta, color = theme.textSecondary)
                // Stated plainly, because not having one is the point.
                Text("Telefon raqami ulanmagan", style = MillyType.Timestamp, color = theme.textTertiary)
            }
            Chevron()
        }
    }
}

@Composable
private fun Chevron() {
    Icon(
        Icons.Rounded.ChevronRight,
        null,
        tint = theme.textDisabled,
        modifier = Modifier.size(18.dp),
    )
}
