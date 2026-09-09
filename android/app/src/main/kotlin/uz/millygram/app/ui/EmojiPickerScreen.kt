package uz.millygram.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.Space
import uz.millygram.app.theme.theme

/**
 * Choosing which emoji stands in for a contact.
 *
 * The choice is this device's, and it stops here. Nothing on this screen is
 * sent anywhere, the contact cannot see it and cannot influence it, and there
 * is no field on the wire for it to travel in. It is a note the owner of the
 * phone keeps about somebody, like the local name for a contact.
 *
 * Which is worth saying on the screen itself, because a picker that looks like
 * a profile editor invites the assumption that the other person will see the
 * result — and acting on that assumption is how somebody ends up believing they
 * have told a contact something they have not.
 */
@Composable
fun EmojiPickerScreen(
    /** The contact this choice is about. Shown so the screen is unambiguous. */
    peerName: String,
    selected: String,
    onPick: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val catalogue = remember { EmojiAvatars.catalogue(context) }
    var current by remember(selected) { mutableStateOf(selected) }

    Column(
        Modifier
            .fillMaxSize()
            .background(theme.surface)
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
            Text(peerName, style = MillyType.Label, color = theme.textPrimary)
        }

        Text(
            "Bu rasm faqat sizning telefoningizda ko‘rinadi",
            style = MillyType.Meta,
            color = theme.textSecondary,
            textAlign = TextAlign.Start,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp),
        )

        LazyVerticalGrid(
            columns = GridCells.Adaptive(minSize = 76.dp),
            contentPadding = PaddingValues(16.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxSize().navigationBarsPadding(),
        ) {
            items(catalogue, key = { it }) { id ->
                val chosen = id == current
                // Selection is shown by size and a mark beneath, not by a ring.
                // A ring here would contradict the whole point of the avatar
                // being borderless — the grid would teach the eye a frame that
                // the rest of the app then does not have.
                val scale by animateFloatAsState(
                    targetValue = if (chosen) 1.16f else 1f,
                    animationSpec = spring(dampingRatio = 0.55f, stiffness = 620f),
                    label = "pick",
                )
                Column(
                    modifier = Modifier
                        .size(72.dp)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                        ) {
                            current = id
                            onPick(id)
                        },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    // Idle in the grid: sixty-eight running decoders would be a
                    // furnace. The still frame still breathes, so the grid is
                    // alive without being a fan heater.
                    EmojiAvatar(
                        emojiId = id,
                        size = 54.dp,
                        modifier = Modifier.graphicsLayer { scaleX = scale; scaleY = scale },
                        motion = EmojiMotion.Idle,
                        tappable = false,
                    )
                    Box(
                        Modifier
                            .padding(top = 5.dp)
                            .size(5.dp)
                            .clip(CircleShape)
                            .background(if (chosen) theme.accent else Color.Transparent),
                    )
                }
            }
        }
    }
}
