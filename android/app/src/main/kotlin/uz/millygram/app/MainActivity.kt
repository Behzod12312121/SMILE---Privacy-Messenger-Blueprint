package uz.millygram.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import uz.millygram.app.theme.MillyGramTheme
import uz.millygram.app.theme.theme
import uz.millygram.app.ui.ChatListScreen
import uz.millygram.app.ui.ConversationScreen
import uz.millygram.app.ui.Message
import uz.millygram.app.ui.NewChatScreen
import uz.millygram.app.ui.SafetyNumberScreen
import uz.millygram.app.ui.SettingsScreen
import uz.millygram.app.ui.TimelineItem

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MillyGramTheme {
                MillyGramApp(
                    onScreenSecurityChanged = ::applyScreenSecurity,
                    initialScreenSecurity = SampleData.account.screenLock,
                )
            }
        }
        applyScreenSecurity(SampleData.account.screenLock)
    }

    /**
     * FLAG_SECURE keeps the window out of screenshots, screen recordings and
     * the recents thumbnail.
     *
     * That last one is the part people miss: without this, Android caches an
     * image of whatever was on screen when the app was backgrounded, and it is
     * readable by anyone who picks up an unlocked handset. The settings toggle
     * that controls this used to be decorative; a security control that does
     * nothing is worse than none, because it is believed.
     */
    private fun applyScreenSecurity(enabled: Boolean) {
        if (enabled) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

private object Route {
    const val CHATS = "chats"
    const val CONVERSATION = "conversation/{aci}"
    const val NEW_CHAT = "new-chat"
    const val SETTINGS = "settings"
    const val SAFETY_NUMBER = "safety/{aci}"

    fun conversation(aci: String) = "conversation/$aci"
    fun safety(aci: String) = "safety/$aci"
}

/**
 * Navigation.
 *
 * Transitions are 220ms and horizontal — fast enough not to be waited on, long
 * enough to show direction. Anything slower starts to feel like the app is
 * thinking, which is the opposite of what a messenger should convey.
 */
@Composable
private fun MillyGramApp(
    onScreenSecurityChanged: (Boolean) -> Unit,
    initialScreenSecurity: Boolean,
) {
    val navController = rememberNavController()

    // Local UI state stands in for the client until the ViewModel lands. It is
    // deliberately shaped like the real thing: a timeline that grows by append,
    // and toggles that are the source of truth for their rows.
    val timeline = remember { mutableStateListOf<TimelineItem>().apply { addAll(SampleData.timeline) } }
    var readReceipts by remember { mutableStateOf(SampleData.account.readReceipts) }
    var screenLock by remember { mutableStateOf(initialScreenSecurity) }
    var verified by remember { mutableStateOf(false) }

    NavHost(
        navController = navController,
        startDestination = Route.CHATS,
        modifier = Modifier.fillMaxSize().background(theme.background),
        enterTransition = { slideIn() },
        exitTransition = { fadeOutSlightly() },
        popEnterTransition = { fadeInSlightly() },
        popExitTransition = { slideOut() },
    ) {
        composable(Route.CHATS) {
            ChatListScreen(
                conversations = SampleData.conversations,
                onOpenConversation = { navController.navigate(Route.conversation(it.aci)) },
                onNewChat = { navController.navigate(Route.NEW_CHAT) },
                onSettings = { navController.navigate(Route.SETTINGS) },
            )
        }

        composable(Route.CONVERSATION) { entry ->
            val aci = entry.arguments?.getString("aci").orEmpty()
            val peer = SampleData.conversations.firstOrNull { it.aci == aci }

            ConversationScreen(
                peerAci = aci,
                peerName = peer?.displayName ?: "Suhbat",
                timeline = timeline,
                onBack = { navController.popBackStack() },
                onOpenProfile = { navController.navigate(Route.safety(aci)) },
                onSend = { body ->
                    timeline += TimelineItem.Bubble(
                        Message(
                            id = System.currentTimeMillis(),
                            body = body,
                            timestamp = "hozir",
                            outgoing = true,
                            delivered = false,
                        ),
                    )
                },
            )
        }

        composable(Route.NEW_CHAT) {
            NewChatScreen(
                recents = SampleData.recents,
                myUsername = SampleData.account.username,
                onCancel = { navController.popBackStack() },
                onSelect = {
                    navController.popBackStack()
                    navController.navigate(Route.conversation(it.aci))
                },
                onNewGroup = {},
            )
        }

        composable(Route.SETTINGS) {
            SettingsScreen(
                account = SampleData.account.copy(readReceipts = readReceipts, screenLock = screenLock),
                onBack = { navController.popBackStack() },
                onSafetyNumber = { navController.navigate(Route.safety(SampleData.conversations[1].aci)) },
                onDevices = {},
                onToggleReadReceipts = { readReceipts = it },
                onToggleScreenLock = {
                    screenLock = it
                    onScreenSecurityChanged(it)
                },
            )
        }

        composable(Route.SAFETY_NUMBER) { entry ->
            val aci = entry.arguments?.getString("aci").orEmpty()
            val peer = SampleData.conversations.firstOrNull { it.aci == aci }

            SafetyNumberScreen(
                peerAci = aci,
                peerName = peer?.displayName ?: "Suhbatdosh",
                peerGivenName = peer?.displayName?.substringBefore(' ') ?: "Suhbatdosh",
                safetyNumber = SampleData.account.safetyNumber,
                verified = verified,
                onBack = { navController.popBackStack() },
                onMarkVerified = { verified = !verified },
            )
        }
    }
}

private const val TRANSITION_MS = 220

private fun AnimatedContentTransitionScope<*>.slideIn() =
    slideIntoContainer(AnimatedContentTransitionScope.SlideDirection.Left, tween(TRANSITION_MS))

private fun AnimatedContentTransitionScope<*>.slideOut() =
    slideOutOfContainer(AnimatedContentTransitionScope.SlideDirection.Right, tween(TRANSITION_MS))

private fun fadeOutSlightly() = androidx.compose.animation.fadeOut(tween(TRANSITION_MS))

private fun fadeInSlightly() = androidx.compose.animation.fadeIn(tween(TRANSITION_MS))
