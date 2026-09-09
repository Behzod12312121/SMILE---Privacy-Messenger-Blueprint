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
import androidx.compose.material.icons.rounded.Add
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
import uz.millygram.client.Handles
import uz.millygram.app.data.MillygramSession
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
    onSettings: () -> Unit,
    /** Groups this device is in. Listed apart from private threads, not mixed in. */
    groups: List<Group> = emptyList(),
    onOpenGroup: (Group) -> Unit = {},
    onCreateGroup: () -> Unit = {},
    /** Resolving a complete handle typed into the search field. */
    onStartWithUsername: (String) -> Unit = {},
    /** Why the last attempt to resolve one failed, if it did. */
    startError: String? = null,
    starting: Boolean = false,
    connection: ConnectionState = ConnectionState.Online,
) {
    var query by remember { mutableStateOf("") }
    var section by remember { mutableStateOf(Section.Chats) }
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
        }

        Text(
            text = if (section == Section.Chats) "Suhbatlar" else "Guruhlar",
            style = MillyType.LargeTitle,
            color = theme.textPrimary,
            modifier = Modifier.padding(start = Space.gutter, end = Space.gutter, top = Space.xs, bottom = 12.dp),
        )

        SectionPicker(section, groups.size) { section = it }

        // An empty list and a dead socket look identical, so the state that
        // means "you may be missing messages" has to say so. Shown on both
        // sections, because a group is no more reachable than a private thread
        // when the socket is down.
        if (connection != ConnectionState.Online) ConnectionNotice(connection)

        if (section == Section.Groups) {
            GroupsSection(groups, onOpenGroup, onCreateGroup)
            return@Column
        }

        SearchField(query) { query = it }

        // The half of this field that reaches off the device.
        //
        // One field does both jobs, and the discriminator is what makes that
        // possible without a mode switch to get wrong: a bare nickname can only
        // ever be a filter, because it is not a name the gateway will resolve,
        // and a complete handle is unmistakably a request to find somebody. The
        // user types one thing and the shape of it decides.
        val typed = query.trim()
        // An invite is a handle somebody was given rather than one they typed, so
        // the field takes both and the shape decides which it is. Opening one is
        // a decryption, so it is remembered per query rather than repeated on
        // every recomposition.
        val handle = remember(typed) { Handles.usernameFromLink(typed) ?: typed }
        val discoverable = Handles.isValidUsername(handle) &&
            conversations.none { it.username.equals(handle, ignoreCase = true) }

        if (discoverable) StartWithHandle(handle, starting) { onStartWithUsername(handle) }

        if (startError != null) {
            Text(
                startError,
                style = MillyType.Notice,
                color = theme.textSecondary,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(horizontal = Space.gutter, vertical = 6.dp),
            )
        }

        if (conversations.isEmpty() && !discoverable) {
            EmptyChats()
        } else if (shown.isEmpty() && !discoverable) {
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

/** Which half of the dashboard is showing. */
private enum class Section { Chats, Groups }

/**
 * The switch between private threads and groups.
 *
 * Two sections rather than one merged list, because the two behave differently
 * in the one way that matters: a reply in a group goes to everyone in it. A
 * list that mixed them would make that difference a matter of noticing an icon,
 * and the cost of not noticing is a message sent to people who were never meant
 * to read it.
 */
@Composable
private fun SectionPicker(current: Section, groupCount: Int, onPick: (Section) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.gutter, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        SectionTab("Suhbatlar", current == Section.Chats, Modifier.weight(1f)) { onPick(Section.Chats) }
        SectionTab(
            if (groupCount > 0) "Guruhlar  $groupCount" else "Guruhlar",
            current == Section.Groups,
            Modifier.weight(1f),
        ) { onPick(Section.Groups) }
    }
}

@Composable
private fun SectionTab(label: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(if (selected) theme.accentMuted else theme.surface)
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            label,
            style = MillyType.Label,
            color = if (selected) theme.accent else theme.textSecondary,
            maxLines = 1,
        )
    }
}

@Composable
private fun GroupsSection(groups: List<Group>, onOpen: (Group) -> Unit, onCreate: () -> Unit) {
    if (groups.isEmpty()) {
        Column(
            Modifier.fillMaxSize().padding(horizontal = Space.gutter),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                "Hali guruh yo‘q",
                style = MillyType.Name,
                color = theme.textPrimary,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                // Said here rather than discovered later: a group is this
                // device's own list of people, not something the server keeps.
                "Guruh shu qurilmada yaratiladi. Serverda guruh degan narsa yo‘q.",
                style = MillyType.Notice,
                color = theme.textSecondary,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(18.dp))
            CreateGroupButton(onCreate)
        }
        return
    }

    LazyColumn(Modifier.fillMaxSize()) {
        items(groups, key = { it.groupId }) { group -> GroupRow(group) { onOpen(group) } }
        item {
            Box(
                Modifier.fillMaxWidth().padding(horizontal = Space.gutter, vertical = 14.dp),
                contentAlignment = Alignment.Center,
            ) { CreateGroupButton(onCreate) }
        }
        item { Spacer(Modifier.height(Space.xl)) }
    }
}

@Composable
private fun CreateGroupButton(onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(theme.accent)
            .clickable(onClick = onClick)
            .padding(horizontal = 22.dp, vertical = 13.dp),
    ) {
        Icon(Icons.Rounded.Add, null, tint = theme.onAccent, modifier = Modifier.size(20.dp))
        Text("Guruh yaratish", style = MillyType.Label, color = theme.onAccent)
    }
}

@Composable
private fun GroupRow(group: Group, onClick: () -> Unit) {
    val unread = group.unread > 0
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 3.dp)
            .then(if (unread) Modifier.liquidGlow() else Modifier)
            .clip(RoundedCornerShape(18.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = Space.gutter - 8.dp, vertical = 11.dp),
    ) {
        Avatar(null, group.name, 52.dp, emojiId = MillygramSession.GROUP_AVATAR_EMOJI)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Row(verticalAlignment = Alignment.Bottom) {
                Text(
                    group.name,
                    style = MillyType.Name,
                    color = theme.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (group.timestamp.isNotEmpty()) {
                    Spacer(Modifier.width(10.dp))
                    Text(group.timestamp, style = MillyType.Meta, color = theme.textSecondary)
                }
            }
            Text(
                group.preview.ifEmpty { "${group.members.size} ishtirokchi" },
                style = MillyType.Preview,
                color = theme.textSecondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
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
                Text("Qidirish, @nomi.42 yoki taklif", style = MillyType.Preview, color = theme.textTertiary)
            }
            BasicTextField(
                value = query,
                onValueChange = onQueryChange,
                singleLine = true,
                // Typing sends nothing. A complete handle offers a row to tap,
                // and only that tap asks the gateway anything — which matters,
                // because a lookup per keystroke would empty a whole day of the
                // discovery budget before the name was finished.
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
    val unread = conversation.unread > 0
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            // Room for the glow to sit outside the content without the border
            // touching the row above or the screen edge.
            .padding(horizontal = 8.dp, vertical = 3.dp)
            .then(if (unread) Modifier.liquidGlow() else Modifier)
            .clip(RoundedCornerShape(18.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = Space.gutter - 8.dp, vertical = 11.dp),
    ) {
        Avatar(
            conversation.avatarSeed,
            conversation.displayName,
            52.dp,
            emojiId = conversation.avatarEmoji,
        )
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
private fun EmptyChats() {
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
            "Doʻstingizning toʻliq nomini yuqoridagi qidiruvga kiriting, masalan @dilnoza.4417 — telefon raqami kerak emas.",
            style = MillyType.Notice,
            color = theme.textSecondary,
            textAlign = TextAlign.Center,
        )
    }
}


/**
 * The row that turns a typed handle into a conversation.
 *
 * Deliberately a row and not a live result: resolving a name is a request to
 * the gateway, rationed to a dozen or so, and firing one per keystroke would
 * spend a day of that budget before the name was finished being typed. So the
 * tap is the request, and everything before it stays on the device.
 */
@Composable
private fun StartWithHandle(handle: String, busy: Boolean, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.gutter)
            .padding(bottom = 10.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(theme.field)
            .clickable(enabled = !busy, onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 12.dp),
    ) {
        Icon(Icons.Rounded.Search, null, tint = theme.accent, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text("@" + handle, style = MillyType.Name, color = theme.textPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                if (busy) "Qidirilmoqda…" else "Suhbat boshlash",
                style = MillyType.Meta,
                color = theme.textTertiary,
            )
        }
    }
}