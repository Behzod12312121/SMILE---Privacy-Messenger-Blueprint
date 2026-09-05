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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.EditNote
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Radius
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * The chat list.
 *
 * One list, and only one. There are no channels, no bots, no stories and no
 * promoted content to sort past, so the folder tabs every other messenger
 * needs simply have nothing to organise. That absence is the single biggest
 * visual difference here, and it is a consequence of the product rather than a
 * styling choice.
 *
 * There are also no separators between rows. Spacing carries the structure,
 * which reads calmer and stops the list looking like a spreadsheet.
 */
@Composable
fun ChatListScreen(
    conversations: List<Conversation>,
    onOpenConversation: (Conversation) -> Unit,
    onNewChat: () -> Unit,
    onSettings: () -> Unit,
    connection: ConnectionState = ConnectionState.Online,
) {
    var query by remember { mutableStateOf("") }
    val shown = remember(conversations, query) {
        if (query.isBlank()) {
            conversations
        } else {
            conversations.filter { it.displayName.contains(query, ignoreCase = true) }
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(theme.background)
            .statusBarsPadding(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp).height(44.dp),
        ) {
            IconAction(Icons.Rounded.Settings, "Sozlamalar", theme.textSecondary, onSettings)
            Spacer(Modifier.weight(1f))
            IconAction(Icons.Rounded.EditNote, "Yangi suhbat", theme.accent, onNewChat)
        }

        Text(
            text = "Suhbatlar",
            style = MillyType.LargeTitle,
            color = theme.textPrimary,
            modifier = Modifier.padding(start = Space.gutter, end = Space.gutter, top = Space.xs, bottom = 14.dp),
        )

        SearchField(query) { query = it }

        // An empty list and a dead socket look identical, so the state that
        // means "you may be missing messages" has to say so.
        if (connection != ConnectionState.Online) ConnectionNotice(connection)

        if (conversations.isEmpty()) {
            EmptyChats(onNewChat)
        } else if (shown.isEmpty()) {
            NoMatches(query)
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(shown, key = { it.aci }) { conversation ->
                    ConversationRow(conversation) { onOpenConversation(conversation) }
                }
                item { Spacer(Modifier.height(Space.xl)) }
            }
        }
    }
}

@Composable
private fun IconAction(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    description: String,
    tint: androidx.compose.ui.graphics.Color,
    onClick: () -> Unit,
) {
    Box(
        Modifier.size(Space.minTouchTarget).clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, description, tint = tint, modifier = Modifier.size(23.dp))
    }
}

@Composable
private fun SearchField(query: String, onQueryChange: (String) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(9.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.gutter)
            .padding(bottom = 14.dp)
            .clip(RoundedCornerShape(Radius.field))
            .background(theme.field)
            .height(40.dp)
            .padding(horizontal = 13.dp),
    ) {
        Icon(Icons.Rounded.Search, null, tint = theme.textTertiary, modifier = Modifier.size(17.dp))
        Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
            if (query.isEmpty()) {
                Text("Qidirish", style = MillyType.Preview, color = theme.textTertiary)
            }
            BasicTextField(
                value = query,
                onValueChange = onQueryChange,
                singleLine = true,
                // Names only, and only names already on this device. Nothing
                // typed here is sent anywhere.
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                textStyle = MillyType.Preview.merge(TextStyle(color = theme.textPrimary)),
                cursorBrush = SolidColor(theme.accent),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun NoMatches(query: String) {
    Box(Modifier.fillMaxWidth().padding(Space.xxl), contentAlignment = Alignment.Center) {
        Text(
            "\"$query\" boʻyicha hech narsa topilmadi",
            style = MillyType.Notice,
            color = theme.textSecondary,
        )
    }
}

@Composable
private fun ConversationRow(conversation: Conversation, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = Space.gutter, vertical = 11.dp),
    ) {
        Avatar(conversation.aci, conversation.displayName, 52.dp)
        Spacer(Modifier.width(14.dp))

        Column(
            Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Row(verticalAlignment = Alignment.Bottom) {
                // One weight only. A second weighted spacer here splits the free
                // space between the two, which parks the timestamp mid-row
                // whenever the name is short instead of flush right.
                Text(
                    text = conversation.displayName,
                    style = MillyType.Name,
                    color = theme.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(10.dp))
                Text(conversation.timestamp, style = MillyType.Meta, color = theme.textTertiary)
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                if (conversation.outgoing) {
                    DeliveryTick(theme.accent, Modifier.padding(end = 5.dp))
                }
                Text(
                    text = buildAnnotatedString {
                        conversation.previewPrefix?.let {
                            withStyle(SpanStyle(color = theme.textTertiary)) { append("$it: ") }
                        }
                        append(conversation.preview)
                    },
                    style = MillyType.Preview,
                    color = theme.textSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(Space.sm))
                UnreadBadge(conversation.unread)
            }
        }
    }
}

@Composable
private fun ConnectionNotice(connection: ConnectionState) {
    val connecting = connection == ConnectionState.Connecting
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(if (connecting) theme.noticeSurface else theme.dangerSurface)
            .padding(horizontal = Space.gutter, vertical = 9.dp),
    ) {
        Text(
            if (connecting) "Ulanmoqda…" else "Ulanish yoʻq. Yangi xabarlar kelmayapti.",
            style = MillyType.Timestamp,
            color = if (connecting) theme.noticeStrong else theme.danger,
        )
    }
}

/**
 * The first thing a new account sees. It says what to do next rather than
 * leaving a blank page that reads as a broken screen.
 */
@Composable
private fun EmptyChats(onNewChat: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = Space.xxl),
    ) {
        Spacer(Modifier.height(96.dp))
        Text(
            "Hali suhbat yoʻq",
            style = MillyType.Title,
            color = theme.textPrimary,
        )
        Spacer(Modifier.height(Space.sm))
        Text(
            "Do‘stingizning foydalanuvchi nomini kiriting — telefon raqami kerak emas.",
            style = MillyType.Notice,
            color = theme.textSecondary,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(Space.xl))
        Box(
            Modifier
                .clip(RoundedCornerShape(12.dp))
                .background(theme.accent)
                .clickable(onClick = onNewChat)
                .padding(horizontal = Space.xl, vertical = 12.dp),
        ) {
            Text("Suhbat boshlash", style = MillyType.Label, color = theme.onAccent)
        }
    }
}
