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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * One group: who is in it, and the two things that can be done about that.
 *
 * "Delete" is deliberately absent, and the screen says why rather than leaving
 * a gap somebody reads as an oversight. A group is a label a handful of clients
 * agree to use, held by each of them. There is no object on the server to
 * remove and no message that could make the others forget theirs. Leaving is
 * the honest operation: it tells the others to stop addressing this device and
 * drops the local copy. Offering "delete for everyone" would be a promise the
 * protocol cannot keep.
 */
@Composable
fun GroupDetailScreen(
    group: Group,
    /** Display name per ACI, for members this device knows. */
    nameOf: (String) -> String,
    /** People not in the group who could be added. */
    candidates: List<Conversation>,
    busy: Boolean,
    error: String?,
    onSetMembers: (List<String>) -> Unit,
    onLeave: () -> Unit,
    onBack: () -> Unit,
) {
    var adding by remember { mutableStateOf(false) }
    var confirmLeave by remember { mutableStateOf(false) }

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
            Text(group.name, style = MillyType.Label, color = theme.textPrimary)
        }

        Column(
            Modifier.fillMaxWidth().padding(vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            EmojiAvatar(emojiId = GROUP_EMOJI, size = 84.dp, motion = EmojiMotion.Loop)
            Spacer(Modifier.height(8.dp))
            Text(group.name, style = MillyType.LargeTitle, color = theme.textPrimary)
            Text(
                "${group.members.size} ishtirokchi",
                style = MillyType.Meta,
                color = theme.textSecondary,
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

        LazyColumn(Modifier.fillMaxSize().navigationBarsPadding()) {
            item {
                Text(
                    "Ishtirokchilar",
                    style = MillyType.Meta,
                    color = theme.textSecondary,
                    modifier = Modifier.padding(horizontal = Space.gutter, vertical = 8.dp),
                )
            }

            items(group.members, key = { it }) { aci ->
                MemberRow(
                    label = nameOf(aci),
                    seed = null,
                    trailing = {
                        // Removing the last member would leave a group of one,
                        // which is a note to self wearing a group's clothes.
                        if (group.members.size > 1 && !busy) {
                            Text(
                                "Chiqarish",
                                style = MillyType.Meta,
                                color = theme.accent,
                                modifier = Modifier
                                    .clip(RoundedCornerShape(10.dp))
                                    .clickable { onSetMembers(group.members.filterNot { it == aci }) }
                                    .padding(horizontal = 10.dp, vertical = 6.dp),
                            )
                        }
                    },
                )
            }

            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier
                        .padding(horizontal = 8.dp, vertical = 8.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .clickable { adding = !adding }
                        .padding(horizontal = Space.gutter - 8.dp, vertical = 10.dp),
                ) {
                    Icon(Icons.Rounded.Add, null, tint = theme.accent, modifier = Modifier.size(20.dp))
                    Text("Ishtirokchi qo‘shish", style = MillyType.Label, color = theme.accent)
                }
            }

            if (adding) {
                if (candidates.isEmpty()) {
                    item {
                        Text(
                            "Qo‘shish uchun boshqa suhbat yo‘q.",
                            style = MillyType.Notice,
                            color = theme.textSecondary,
                            modifier = Modifier.padding(horizontal = Space.gutter, vertical = 6.dp),
                        )
                    }
                } else {
                    items(candidates, key = { "add-${it.aci}" }) { contact ->
                        MemberRow(
                            label = contact.displayName,
                            seed = contact.avatarSeed,
                            emoji = contact.avatarEmoji,
                            trailing = {
                                Box(
                                    Modifier
                                        .size(24.dp)
                                        .clip(CircleShape)
                                        .background(theme.surface)
                                        .clickable(enabled = !busy) {
                                            onSetMembers(group.members + contact.aci)
                                            adding = false
                                        },
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Icon(Icons.Rounded.Check, null, tint = theme.accent, modifier = Modifier.size(16.dp))
                                }
                            },
                        )
                    }
                }
            }

            item {
                Column(Modifier.padding(horizontal = Space.gutter, vertical = 20.dp)) {
                    Text(
                        // The absent button, explained where it would have been.
                        "Guruhni hamma uchun o‘chirib bo‘lmaydi. Guruh — serverdagi narsa emas, " +
                            "har bir qurilmadagi ro‘yxat. Chiqsangiz, boshqalarda qoladi.",
                        style = MillyType.Notice,
                        color = theme.textSecondary,
                    )
                    Spacer(Modifier.height(12.dp))
                    if (!confirmLeave) {
                        LeaveButton("Guruhdan chiqish", busy) { confirmLeave = true }
                    } else {
                        Text(
                            "Chiqasizmi? Yozishmalar shu qurilmadan o‘chadi.",
                            style = MillyType.Notice,
                            color = theme.textPrimary,
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            LeaveButton("Ha, chiqaman", busy, onLeave)
                            Box(
                                Modifier
                                    .clip(RoundedCornerShape(14.dp))
                                    .background(theme.surface)
                                    .clickable { confirmLeave = false }
                                    .padding(horizontal = 18.dp, vertical = 11.dp),
                            ) { Text("Bekor", style = MillyType.Label, color = theme.textSecondary) }
                        }
                    }
                }
            }
            item { Spacer(Modifier.height(Space.xl)) }
        }
    }
}

@Composable
private fun LeaveButton(label: String, busy: Boolean, onClick: () -> Unit) {
    Box(
        Modifier
            .clip(RoundedCornerShape(14.dp))
            .background(theme.surface)
            .clickable(enabled = !busy, onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 11.dp),
    ) {
        Text(label, style = MillyType.Label, color = theme.danger)
    }
}

@Composable
private fun MemberRow(
    label: String,
    seed: ByteArray?,
    emoji: String? = null,
    trailing: @Composable () -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.gutter, vertical = 6.dp),
    ) {
        Avatar(seed, label, 40.dp, emojiId = emoji)
        Spacer(Modifier.width(12.dp))
        Text(
            label,
            style = MillyType.Name,
            color = theme.textPrimary,
            modifier = Modifier.weight(1f),
        )
        trailing()
    }
}

private const val GROUP_EMOJI = "people_hugging"
