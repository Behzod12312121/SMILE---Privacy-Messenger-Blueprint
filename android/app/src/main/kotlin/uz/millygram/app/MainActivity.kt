package uz.millygram.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.launch
import uz.millygram.app.data.AppViewModel
import uz.millygram.app.data.ConversationState
import uz.millygram.app.data.Delivery
import uz.millygram.app.data.MillygramSession
import uz.millygram.app.theme.MillyGramTheme
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.theme
import uz.millygram.app.ui.ChatListScreen
import uz.millygram.app.ui.Contact
import uz.millygram.app.ui.Conversation
import uz.millygram.app.ui.ConnectionState
import uz.millygram.app.ui.ConversationScreen
import uz.millygram.app.ui.DeliveryState
import uz.millygram.app.ui.Message
import uz.millygram.app.ui.NewChatScreen
import uz.millygram.app.ui.OnboardingScreen
import uz.millygram.app.ui.SafetyNumberScreen
import uz.millygram.app.ui.SettingsScreen
import uz.millygram.app.ui.TimelineItem

class MainActivity : ComponentActivity() {

    /**
     * Screen security is on from the first frame rather than after the first
     * composition. A window that is briefly capturable is capturable.
     */
    private var screenSecurity = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyScreenSecurity(true)
        enableEdgeToEdge()
        setContent {
            MillyGramTheme {
                MillyGramApp(onScreenSecurityChanged = ::applyScreenSecurity)
            }
        }
    }

    /**
     * FLAG_SECURE keeps the window out of screenshots, screen recordings and
     * the recents thumbnail. That last one is the part people miss: without it
     * Android caches an image of whatever was on screen when the app was
     * backgrounded, readable by anyone holding an unlocked handset.
     */
    private fun applyScreenSecurity(enabled: Boolean) {
        screenSecurity = enabled
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

@Composable
private fun MillyGramApp(onScreenSecurityChanged: (Boolean) -> Unit) {
    val model: AppViewModel = viewModel()
    val state by model.state.collectAsStateWithLifecycle()

    when (val current = state) {
        is AppViewModel.State.NeedsAccount,
        is AppViewModel.State.Locked,
        is AppViewModel.State.Working,
        is AppViewModel.State.Failed,
        -> {
            val creating = when (current) {
                is AppViewModel.State.Failed -> current.previous is AppViewModel.State.NeedsAccount
                else -> current is AppViewModel.State.NeedsAccount
            }
            OnboardingScreen(
                creating = creating,
                busy = (current as? AppViewModel.State.Working)?.what,
                error = (current as? AppViewModel.State.Failed)?.message,
                defaultServer = model.serverUrl,
                defaultRelay = model.relayUrl,
                onRegister = model::register,
                onUnlock = model::unlock,
                onDismissError = model::dismissError,
            )
        }

        is AppViewModel.State.Ready -> SignedIn(current.session, model, onScreenSecurityChanged)
    }
}

/**
 * Navigation. Transitions are 220ms and horizontal — fast enough not to be
 * waited on, long enough to show direction.
 */
@Composable
private fun SignedIn(
    session: MillygramSession,
    model: AppViewModel,
    onScreenSecurityChanged: (Boolean) -> Unit,
) {
    val navController = rememberNavController()
    val scope = rememberCoroutineScope()
    val conversations by session.conversations.collectAsStateWithLifecycle()
    val identityWarnings by session.identityWarnings.collectAsStateWithLifecycle()
    val status by session.status.collectAsStateWithLifecycle()

    var screenLock by remember { mutableStateOf(true) }

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
                conversations = conversations.map { it.toUi() },
                connection = status.toUi(),
                onOpenConversation = { navController.navigate(Route.conversation(it.aci)) },
                onNewChat = { navController.navigate(Route.NEW_CHAT) },
                onSettings = { navController.navigate(Route.SETTINGS) },
            )
        }

        composable(Route.CONVERSATION) { entry ->
            val aci = entry.arguments?.getString("aci").orEmpty()
            val conversation = conversations.firstOrNull { it.aci == aci }

            ConversationScreen(
                peerAci = aci,
                peerName = conversation?.username ?: aci.take(8),
                timeline = conversation.toTimeline(),
                onBack = { navController.popBackStack() },
                onOpenProfile = { navController.navigate(Route.safety(aci)) },
                // A failure leaves the message on screen marked failed and
                // retryable, so nothing is lost if this throws.
                onSend = { body -> scope.launch { model.send(aci, body) } },
                onRetry = { id -> scope.launch { model.retry(aci, id) } },
                identityChanged = aci in identityWarnings,
            )
        }

        composable(Route.NEW_CHAT) {
            NewChatScreen(
                recents = conversations.map { Contact(it.aci, it.username, it.username) },
                myUsername = session.username,
                onCancel = { navController.popBackStack() },
                onSelect = {
                    navController.popBackStack()
                    navController.navigate(Route.conversation(it.aci))
                },
                // A username typed here has never been seen before, so the
                // send has to resolve it before there is a conversation to open.
                onStartWithUsername = { username ->
                    scope.launch {
                        model.send(username, "Salom!").onSuccess { navController.popBackStack() }
                    }
                },
            )
        }

        composable(Route.SETTINGS) {
            SettingsScreen(
                account = session.toAccount(screenLock),
                onBack = { navController.popBackStack() },
                onToggleScreenLock = {
                    screenLock = it
                    onScreenSecurityChanged(it)
                },
            )
        }

        composable(Route.SAFETY_NUMBER) { entry ->
            val aci = entry.arguments?.getString("aci").orEmpty()
            val conversation = conversations.firstOrNull { it.aci == aci }

            // Computing a safety number needs the peer's identity key, which
            // only exists once a message has passed between the two. Until then
            // the screen says so rather than showing an empty grid.
            val number by produceState(initialValue = null as String?, aci) {
                value = runCatching { session.safetyNumber(aci) }.getOrNull()
            }

            val resolved = number
            if (resolved == null) {
                Box(Modifier.fillMaxSize().background(theme.surface), Alignment.Center) {
                    androidx.compose.material3.Text(
                        "Xavfsizlik raqami xabar almashgandan keyin paydo boʻladi",
                        style = MillyType.Notice,
                        color = theme.textSecondary,
                        modifier = Modifier.padding(uz.millygram.app.theme.Space.xxl),
                    )
                }
            } else {
                var verified by remember { mutableStateOf(false) }
                SafetyNumberScreen(
                    peerAci = aci,
                    peerName = conversation?.username ?: aci.take(8),
                    peerGivenName = (conversation?.username ?: aci.take(8)).substringBefore(' '),
                    safetyNumber = resolved,
                    verified = verified,
                    onBack = { navController.popBackStack() },
                    onMarkVerified = {
                        verified = !verified
                        // Comparing the number is the only thing that resolves
                        // the warning, so acknowledging it here and nowhere
                        // else keeps the banner honest.
                        if (verified) session.acknowledgeIdentityWarning(aci)
                    },
                )
            }
        }
    }

    LaunchedEffect(Unit) { onScreenSecurityChanged(screenLock) }
}

/* ---- mapping session state onto what the screens render ---- */

private fun MillygramSession.Status.toUi(): ConnectionState = when (this) {
    MillygramSession.Status.Online -> ConnectionState.Online
    MillygramSession.Status.Connecting -> ConnectionState.Connecting
    MillygramSession.Status.Offline -> ConnectionState.Offline
}

private val clock = SimpleDateFormat("HH:mm", Locale.getDefault())

private fun ConversationState.toUi(): Conversation {
    val last = messages.lastOrNull()
    return Conversation(
        aci = aci,
        displayName = username,
        username = username,
        preview = last?.body.orEmpty(),
        timestamp = last?.let { clock.format(Date(it.sentAt)) }.orEmpty(),
        outgoing = last?.outgoing ?: false,
    )
}

private fun ConversationState?.toTimeline(): List<TimelineItem> {
    if (this == null) return listOf(TimelineItem.EncryptionNotice)
    return buildList {
        add(TimelineItem.EncryptionNotice)
        messages.forEach { message ->
            add(
                TimelineItem.Bubble(
                    Message(
                        id = message.id,
                        body = message.body,
                        timestamp = clock.format(Date(message.sentAt)),
                        outgoing = message.outgoing,
                        delivery = when (message.delivery) {
                            Delivery.Sending -> DeliveryState.Sending
                            Delivery.Sent -> DeliveryState.Sent
                            Delivery.Failed -> DeliveryState.Failed
                            null -> null
                        },
                    ),
                ),
            )
        }
    }
}

private fun MillygramSession.toAccount(screenLock: Boolean) =
    uz.millygram.app.ui.Account(
        displayName = username,
        username = username,
        screenLock = screenLock,
        language = "Oʻzbekcha (lotin)",
        theme = "Tizim",
        buildHash = BuildConfigHash,
    )

/** The commit this APK was built from, stamped in by Gradle. */
private val BuildConfigHash = BuildConfig.GIT_SHA

private const val TRANSITION_MS = 220

private fun AnimatedContentTransitionScope<*>.slideIn() =
    slideIntoContainer(AnimatedContentTransitionScope.SlideDirection.Left, tween(TRANSITION_MS))

private fun AnimatedContentTransitionScope<*>.slideOut() =
    slideOutOfContainer(AnimatedContentTransitionScope.SlideDirection.Right, tween(TRANSITION_MS))

private fun fadeOutSlightly() = androidx.compose.animation.fadeOut(tween(TRANSITION_MS))

private fun fadeInSlightly() = androidx.compose.animation.fadeIn(tween(TRANSITION_MS))
