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
            SettingsRow(
                label = "Ekran qulfi",
                leading = { LockGlyph(theme.textSecondary, size = 20.dp) },
                trailing = { MillyToggle(account.screenLock, onToggleScreenLock) },
            )
        }

        Spacer(Modifier.padding(top = Space.xl))
        Card {
            // Closing the app does not close the session any more — delivery
            // keeps running so notifications can arrive — so there has to be a
            // way to say stop.
            SettingsRow(
                label = "Qulflash",
                value = "Suhbatlarni yopish",
                leading = { KeyGlyph(theme.textSecondary) },
                trailing = { Chevron() },
                onClick = onLock,
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
            Text("MillyGram 1.0 · Ochiq kodli", style = MillyType.Timestamp, color = theme.textTertiary)
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
            Avatar(account.username, account.displayName, 58.dp)
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
