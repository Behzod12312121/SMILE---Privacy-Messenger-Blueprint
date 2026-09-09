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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Check
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
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * Making a group.
 *
 * The people offered are the ones this device already has a conversation with,
 * and that is not a shortcut. Adding somebody to a group means sending them the
 * roster, so the group cannot contain anybody whose keys this device has never
 * fetched — there would be nowhere to send it. A picker that offered arbitrary
 * handles would be offering something the protocol cannot do.
 *
 * Nothing here reaches the gateway. The group is created locally and announced
 * to the members as ordinary messages; there is no group object on the server
 * to create, and no request that could fail halfway.
 */
@Composable
fun CreateGroupScreen(
    contacts: List<Conversation>,
    busy: Boolean,
    error: String?,
    onCreate: (String, List<String>) -> Unit,
    onBack: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var picked by remember { mutableStateOf(setOf<String>()) }
    val ready = name.isNotBlank() && picked.isNotEmpty() && !busy

    Column(
        Modifier
            .fillMaxSize()
            .background(theme.background)
            .statusBarsPadding(),
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
            Text("Yangi guruh", style = MillyType.Label, color = theme.textPrimary)
            Spacer(Modifier.weight(1f))
            Box(
                Modifier
                    .clip(RoundedCornerShape(14.dp))
                    .background(if (ready) theme.accent else theme.surface)
                    .clickable(enabled = ready) { onCreate(name.trim(), picked.toList()) }
                    .padding(horizontal = 16.dp, vertical = 9.dp),
            ) {
                Text(
                    if (busy) "..." else "Yaratish",
                    style = MillyType.Label,
                    color = if (ready) theme.onAccent else theme.textSecondary,
                )
            }
            Spacer(Modifier.width(6.dp))
        }

        Box(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.gutter, vertical = 8.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(theme.surface)
                .padding(horizontal = 16.dp, vertical = 14.dp),
        ) {
            if (name.isEmpty()) {
                Text("Guruh nomi", style = MillyType.Body, color = theme.textSecondary)
            }
            BasicTextField(
                value = name,
                onValueChange = { if (it.length <= GROUP_NAME_LIMIT) name = it },
                singleLine = true,
                textStyle = MillyType.Body.copy(color = theme.textPrimary),
                cursorBrush = androidx.compose.ui.graphics.SolidColor(theme.accent),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        if (error != null) {
            Text(
                error,
                style = MillyType.Notice,
                color = theme.textSecondary,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(horizontal = Space.gutter, vertical = 4.dp),
            )
        }

        Text(
            if (picked.isEmpty()) "Ishtirokchilarni tanlang" else "${picked.size} tanlandi",
            style = MillyType.Meta,
            color = theme.textSecondary,
            modifier = Modifier.padding(horizontal = Space.gutter, vertical = 8.dp),
        )

        if (contacts.isEmpty()) {
            Column(
                Modifier.fillMaxSize().padding(horizontal = Space.gutter),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text("Avval kimdir bilan yozishing kerak", style = MillyType.Name, color = theme.textPrimary)
                Spacer(Modifier.height(6.dp))
                Text(
                    "Guruhga faqat kalitlari ma’lum bo‘lganlarni qo‘shish mumkin.",
                    style = MillyType.Notice,
                    color = theme.textSecondary,
                    textAlign = TextAlign.Center,
                )
            }
            return@Column
        }

        LazyColumn(Modifier.fillMaxSize().navigationBarsPadding()) {
            items(contacts, key = { it.aci }) { contact ->
                val chosen = contact.aci in picked
                MemberPickRow(contact, chosen) {
                    picked = if (chosen) picked - contact.aci else picked + contact.aci
                }
            }
            item { Spacer(Modifier.height(Space.xl)) }
        }
    }
}

@Composable
private fun MemberPickRow(contact: Conversation, chosen: Boolean, onToggle: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 2.dp)
            .clip(RoundedCornerShape(16.dp))
            .clickable(onClick = onToggle)
            .padding(horizontal = Space.gutter - 8.dp, vertical = 9.dp),
    ) {
        Avatar(contact.avatarSeed, contact.displayName, 44.dp, emojiId = contact.avatarEmoji)
        Spacer(Modifier.width(12.dp))
        Text(
            contact.displayName,
            style = MillyType.Name,
            color = theme.textPrimary,
            modifier = Modifier.weight(1f),
        )
        Box(
            Modifier
                .size(24.dp)
                .clip(CircleShape)
                .background(if (chosen) theme.accent else theme.surface),
            contentAlignment = Alignment.Center,
        ) {
            if (chosen) {
                Icon(Icons.Rounded.Check, null, tint = theme.onAccent, modifier = Modifier.size(16.dp))
            }
        }
    }
}

/** Matches GROUP_NAME_MAX in the protocol; a longer name is refused on the wire. */
private const val GROUP_NAME_LIMIT = 64
