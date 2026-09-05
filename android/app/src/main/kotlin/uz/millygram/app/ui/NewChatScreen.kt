package uz.millygram.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.GroupAdd
import androidx.compose.material3.Icon
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
import androidx.compose.ui.text.input.PlatformImeOptions
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * Starting a conversation.
 *
 * There is no contact-list permission request and no phone-number lookup,
 * because the app never learns either. You find someone by the username they
 * chose. That removes the single most invasive onboarding step in messaging,
 * and it deserves to be said on the screen rather than buried in a policy.
 */
@Composable
fun NewChatScreen(
    recents: List<Contact>,
    myUsername: String,
    onCancel: () -> Unit,
    onSelect: (Contact) -> Unit,
    onNewGroup: () -> Unit,
    /** Starting a conversation with a handle that is not yet a contact. */
    onStartWithUsername: (String) -> Unit = {},
) {
    var query by remember { mutableStateOf("") }

    Column(
        Modifier
            .fillMaxSize()
            .background(theme.background)
            .statusBarsPadding(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().height(46.dp).padding(horizontal = Space.gutter),
        ) {
            Text(
                "Bekor qilish",
                style = MillyType.Label,
                color = theme.accent,
                modifier = Modifier.clickable(onClick = onCancel),
            )
            Spacer(Modifier.weight(1f))
            Text("Yangi suhbat", style = MillyType.Name, color = theme.textPrimary)
            Spacer(Modifier.weight(1f))
            Spacer(Modifier.width(76.dp))
        }

        UsernameField(query) { query = it }

        Row(
            verticalAlignment = Alignment.Top,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.gutter)
                .padding(bottom = 18.dp)
                .clip(RoundedCornerShape(15.dp))
                .background(theme.noticeSurface)
                .padding(horizontal = 15.dp, vertical = 14.dp),
        ) {
            ShieldGlyph(theme.accent, Modifier.padding(top = 2.dp))
            Spacer(Modifier.width(12.dp))
            Text(
                "MillyGram telefon raqamini soʻramaydi. Doʻstlaringizni faqat foydalanuvchi " +
                    "nomi orqali toping — hech kim sizni raqamingiz boʻyicha topa olmaydi.",
                style = MillyType.Notice,
                color = theme.noticeText,
            )
        }

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onNewGroup)
                .padding(horizontal = Space.gutter, vertical = 10.dp),
        ) {
            Box(
                Modifier.size(46.dp).clip(CircleShape).background(theme.accentMuted),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.GroupAdd, null, tint = theme.accent, modifier = Modifier.size(21.dp))
            }
            Spacer(Modifier.width(15.dp))
            Text("Yangi guruh", style = MillyType.Label, color = theme.accent)
        }

        if (query.length >= 3 && recents.none { it.username == query }) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onStartWithUsername(query) }
                    .padding(horizontal = Space.gutter, vertical = 10.dp),
            ) {
                Avatar(query, query, 46.dp)
                Spacer(Modifier.width(14.dp))
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text("@" + query, style = MillyType.Name, color = theme.textPrimary)
                    Text("Suhbat boshlash", style = MillyType.Meta, color = theme.accent)
                }
            }
        }

        SectionHeader("Soʻnggi")

        LazyColumn(Modifier.weight(1f)) {
            items(recents.filter { query.isBlank() || it.username.contains(query, true) }, key = { it.aci }) {
                ContactRow(it) { onSelect(it) }
            }
        }

        Box(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(bottom = 26.dp, top = Space.md),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                "Foydalanuvchi nomingiz: @$myUsername",
                style = MillyType.Timestamp,
                color = theme.textTertiary,
            )
        }
    }
}

@Composable
private fun UsernameField(value: String, onChange: (String) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.gutter)
            .padding(top = 14.dp, bottom = 16.dp)
            .clip(RoundedCornerShape(13.dp))
            .background(theme.field)
            .border(1.5.dp, theme.accent, RoundedCornerShape(13.dp))
            .height(46.dp)
            .padding(horizontal = 15.dp),
    ) {
        Text("@", style = MillyType.Label, color = theme.textTertiary)
        Spacer(Modifier.width(2.dp))
        Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
            if (value.isEmpty()) {
                Text("foydalanuvchi nomi", style = MillyType.Preview, color = theme.textTertiary)
            }
            BasicTextField(
                value = value,
                // Usernames are ASCII by protocol rule — allowing Unicode would
                // let a lookalike handle impersonate someone — so the field
                // filters as you type rather than failing at submit.
                onValueChange = { onChange(it.lowercase().filter { c -> c.isLetterOrDigit() || c == '_' }) },
                singleLine = true,
                // A contact's handle is identifying too; it should not end up
                // in a cloud keyboard's learned dictionary either.
                keyboardOptions = KeyboardOptions(
                    autoCorrectEnabled = false,
                    platformImeOptions = PlatformImeOptions("noPersonalizedLearning"),
                ),
                textStyle = LocalTextStyle.current.merge(MillyType.Body).merge(
                    androidx.compose.ui.text.TextStyle(color = theme.textPrimary),
                ),
                cursorBrush = SolidColor(theme.accent),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun ContactRow(contact: Contact, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = Space.gutter, vertical = 9.dp),
    ) {
        Avatar(contact.aci, contact.displayName, 46.dp)
        Spacer(Modifier.width(14.dp))
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                contact.displayName,
                style = MillyType.Name,
                color = theme.textPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text("@${contact.username}", style = MillyType.Meta, color = theme.textTertiary)
        }
    }
}
