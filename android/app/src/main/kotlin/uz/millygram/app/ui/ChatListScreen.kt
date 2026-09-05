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
) {
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

        SearchField()

        LazyColumn(Modifier.fillMaxSize()) {
            items(conversations, key = { it.aci }) { conversation ->
                ConversationRow(conversation) { onOpenConversation(conversation) }
            }
            item { Spacer(Modifier.height(Space.xl)) }
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
private fun SearchField() {
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
        Text("Qidirish", style = MillyType.Preview, color = theme.textTertiary)
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
