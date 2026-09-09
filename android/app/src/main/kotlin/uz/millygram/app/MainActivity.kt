package uz.millygram.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.compose.runtime.DisposableEffect
import androidx.fragment.app.FragmentActivity
import uz.millygram.app.ui.LockedScreen
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.runtime.saveable.rememberSaveable
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
import uz.millygram.app.DeliveryService
import uz.millygram.app.data.AppViewModel
import uz.millygram.app.data.ConversationState
import uz.millygram.app.data.Delivery
import uz.millygram.app.data.MillygramSession
import uz.millygram.app.data.NotificationDetail
import uz.millygram.app.theme.MillyGramTheme
import uz.millygram.app.theme.MillyType
import uz.millygram.app.theme.theme
import androidx.activity.compose.rememberLauncherForActivityResult
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import uz.millygram.app.ui.BackupScreen
import uz.millygram.app.ui.ChatListScreen
import uz.millygram.app.ui.CreateGroupScreen
import uz.millygram.app.ui.Group
import uz.millygram.app.ui.GroupDetailScreen
import uz.millygram.app.ui.Conversation
import uz.millygram.app.ui.ConnectionState
import uz.millygram.app.ui.ConversationScreen
import uz.millygram.app.ui.DeliveryState
import uz.millygram.app.ui.Message
import uz.millygram.app.ui.OnboardingScreen
import uz.millygram.app.ui.RecoveryNumberScreen
import uz.millygram.app.ui.RecoveryScreen
import uz.millygram.app.ui.EmojiPickerScreen
import uz.millygram.app.ui.SafetyNumberScreen
import uz.millygram.app.ui.SettingsScreen
import uz.millygram.app.ui.TimelineItem

class MainActivity : androidx.fragment.app.FragmentActivity() {

    /**
     * Screen security is on from the first frame rather than after the first
     * composition. A window that is briefly capturable is capturable.
     */
    private var screenSecurity = true

    /**
     * Asked for once, at the top. Without it Android 13 and later drop every
     * notification silently, which looks exactly like a messenger that does not
     * work.
     */
    private val askForNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // On in release from the first frame, before any content is composed.
        // Off by default in a debug build: FLAG_SECURE blocks screencap, and a
        // debug build is already fully readable over adb, so keeping it here
        // protects nothing and makes the app impossible to screenshot while
        // developing it. The toggle in Settings still works either way, so the
        // behaviour can be checked on demand.
        applyScreenSecurity(!BuildConfig.DEBUG)
        openRequest = intent.getStringExtra(DeliveryService.EXTRA_CONVERSATION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            askForNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        enableEdgeToEdge()
        setContent {
            MillyGramTheme {
                MillyGramApp(
                    onScreenSecurityChanged = ::applyScreenSecurity,
                    openConversation = openRequest,
                )
            }
        }
    }

    /**
     * FLAG_SECURE keeps the window out of screenshots, screen recordings and
     * the recents thumbnail. That last one is the part people miss: without it
     * Android caches an image of whatever was on screen when the app was
     * backgrounded, readable by anyone holding an unlocked handset.
     */
    /**
     * The conversation a tapped notification asked for, if any.
     *
     * Read as state so a tap that arrives while the activity is already up
     * still moves the screen, rather than only working from cold.
     */
    private var openRequest by mutableStateOf<String?>(null)

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        openRequest = intent.getStringExtra(DeliveryService.EXTRA_CONVERSATION)
    }

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
    const val AVATAR_EMOJI = "avatar-emoji/{aci}"
    const val CREATE_GROUP = "create-group"
    const val GROUP_DETAIL = "group/{groupId}"
    const val BACKUP = "backup"
    const val RECOVERY_NUMBER = "recovery-number"

    fun conversation(aci: String) = "conversation/$aci"
    fun safety(aci: String) = "safety/$aci"
    fun avatarEmoji(aci: String) = "avatar-emoji/$aci"
    fun groupDetail(groupId: String) = "group/$groupId"
}

@Composable
private fun MillyGramApp(
    onScreenSecurityChanged: (Boolean) -> Unit,
    openConversation: String? = null,
) {
    val model: AppViewModel = viewModel()
    val state by model.state.collectAsStateWithLifecycle()

    // Which step of a recovery the user is on, held here rather than read back
    // out of the view model. The model reports CodeSent, then Working while the
    // account is rebuilt, and Working carries no number — driving the screen
    // from it alone would drop the user back to the phone-number step mid-flight.
    // Saveable so a rotation does not lose a code that has already been spent.
    var recovering by rememberSaveable { mutableStateOf(false) }
    var recoveryNumber by rememberSaveable { mutableStateOf("") }
    if (state is AppViewModel.State.CodeSent) {
        recovering = true
        recoveryNumber = (state as AppViewModel.State.CodeSent).phoneNumber
    }

    when (val current = state) {
        is AppViewModel.State.CodeSent,
        is AppViewModel.State.NeedsAccount,
        is AppViewModel.State.Locked,
        is AppViewModel.State.Working,
        is AppViewModel.State.Failed,
        -> {
            // A failure during recovery keeps the user in the recovery flow.
            // Dropping them back to the signup screen after a mistyped code
            // would make them start over for no reason.
            if (recovering) {
                RecoveryScreen(
                    codeSent = recoveryNumber.isNotEmpty(),
                    phoneNumber = recoveryNumber,
                    busy = (current as? AppViewModel.State.Working)?.what,
                    error = (current as? AppViewModel.State.Failed)?.message,
                    onSendCode = { number -> model.startRecovery(number, model.serverUrl, model.relayUrl) },
                    onRecover = { code, passphrase -> model.recover(recoveryNumber, code, passphrase) },
                    onDismissError = model::dismissError,
                    onBack = {
                        recovering = false
                        recoveryNumber = ""
                        model.cancelRecovery()
                        model.dismissError()
                    },
                )
                return
            }

            val creating = when (current) {
                is AppViewModel.State.Failed -> current.previous is AppViewModel.State.NeedsAccount
                else -> current is AppViewModel.State.NeedsAccount
            }
            val context = androidx.compose.ui.platform.LocalContext.current
            val scope = rememberCoroutineScope()
            var chosen by remember { mutableStateOf<ByteArray?>(null) }
            val pick = rememberLauncherForActivityResult(
                ActivityResultContracts.OpenDocument(),
            ) { uri ->
                if (uri == null) return@rememberLauncherForActivityResult
                scope.launch {
                    chosen = runCatching {
                        withContext(Dispatchers.IO) {
                            context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        }
                    }.getOrNull()
                }
            }

            OnboardingScreen(
                creating = creating,
                onRestore = { passphrase, server, relay ->
                    chosen?.let { model.restore(it, passphrase, server, relay) }
                },
                restoreFileChosen = chosen != null,
                onChooseRestoreFile = { pick.launch(arrayOf("*/*")) },
                busy = (current as? AppViewModel.State.Working)?.what,
                error = (current as? AppViewModel.State.Failed)?.message,
                defaultServer = model.serverUrl,
                defaultRelay = model.relayUrl,
                onRegister = model::register,
                onUnlock = model::unlock,
                onDismissError = model::dismissError,
                onRecoverAccount = if (creating) ({ recovering = true }) else null,
            )
        }

        is AppViewModel.State.Ready -> {
            val session = current.session

            // Re-locks whenever the app leaves the foreground. That is the
            // behaviour of the banking apps this is modelled on, and it is the
            // only version that means anything: a lock that survives being
            // switched away from and back is a lock somebody can walk past by
            // opening the recents list.
            val requireUnlock by session.requireUnlockState.collectAsStateWithLifecycle()
            // Deliberately `remember` and not `rememberSaveable`. The saved
            // bundle outlives the process — it is exactly what Android hands
            // back when it has killed the app for memory and rebuilt it from
            // the recents entry — so a saveable flag would restore as `true`
            // and drop whoever tapped the thumbnail straight into the
            // conversations without a prompt. Process death is precisely the
            // moment this gate has to re-assert itself, not the moment it is
            // allowed to remember it was satisfied an hour ago. The cost is a
            // prompt after a rotation, which is what every banking app on the
            // same market does.
            var unlocked by remember { mutableStateOf(!session.requireUnlock) }
            var lockError by remember { mutableStateOf<String?>(null) }
            val activity = androidx.compose.ui.platform.LocalContext.current as? FragmentActivity
            val scope = rememberCoroutineScope()
            val lifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current

            val ask: () -> Unit = {
                // No host to put a prompt on top of is a reason the gate cannot
                // run, not permission to skip it. The old code unlocked here,
                // which meant anything that composed this tree outside a
                // FragmentActivity — a future host activity, a preview, a test
                // harness someone points at the real vault — walked past the
                // lock silently. The passphrase remains the way through, and the
                // screen below offers it.
                val host = activity
                if (host == null) {
                    lockError = "Barmoq izi soʻrovini bu yerda koʻrsatib boʻlmadi. Parol bilan kiring."
                } else {
                    scope.launch {
                        when (val outcome = AppLock.prompt(host)) {
                            is AppLock.Outcome.Passed -> { unlocked = true; lockError = null }
                            is AppLock.Outcome.Dismissed -> Unit
                            is AppLock.Outcome.Unavailable -> {
                                // Never a silent pass, and never a dead end.
                                // If the sensor has gone or the user is locked
                                // out, the way through is the passphrase, which
                                // is still the thing that actually holds the
                                // vault shut.
                                lockError = outcome.reason.ifBlank {
                                    "Barmoq izi ishlamadi. Parol bilan kiring."
                                }
                            }
                        }
                    }
                }
            }

            if (requireUnlock) {
                DisposableEffect(lifecycle, requireUnlock) {
                    val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
                        if (event == androidx.lifecycle.Lifecycle.Event.ON_STOP) {
                            unlocked = false
                            lockError = null
                        }
                    }
                    lifecycle.lifecycle.addObserver(observer)
                    onDispose { lifecycle.lifecycle.removeObserver(observer) }
                }
                LaunchedEffect(unlocked) { if (!unlocked) ask() }
            }

            if (requireUnlock && !unlocked) {
                LockedScreen(
                    error = lockError,
                    onUnlock = ask,
                    // The escape hatch the biometric gate has to have. It closes
                    // the session outright and asks for the passphrase, which is
                    // strictly stronger than the fingerprint it replaces — so a
                    // phone whose sensor has died, or which never had one under
                    // this host, is not a phone with an unreachable account.
                    onUsePassphrase = model::lock,
                )
            } else {
                SignedIn(session, model, onScreenSecurityChanged, openConversation)
            }
        }
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
    openConversation: String? = null,
) {
    val navController = rememberNavController()
    val scope = rememberCoroutineScope()
    val context = androidx.compose.ui.platform.LocalContext.current
    val conversations by session.conversations.collectAsStateWithLifecycle()
    val groups by session.groups.collectAsStateWithLifecycle()
    val identityWarnings by session.identityWarnings.collectAsStateWithLifecycle()
    val status by session.status.collectAsStateWithLifecycle()

    var screenLock by remember { mutableStateOf(!BuildConfig.DEBUG) }
    var startError by remember { mutableStateOf<String?>(null) }
    var notificationDetail by remember { mutableStateOf(session.notificationDetail) }
    var starting by remember { mutableStateOf(false) }

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
                // Private threads only. A group thread lives in the same store
                // and would otherwise appear in both lists.
                conversations = conversations.filter { it.groupId == null }.map { it.toUi() },
                connection = status.toUi(),
                groups = groups.map { summary ->
                    val thread = conversations.firstOrNull { it.aci == MillygramSession.groupThreadKey(summary.groupId) }
                    Group(
                        groupId = summary.groupId,
                        name = summary.name,
                        members = summary.members,
                        preview = thread?.messages?.lastOrNull()?.body.orEmpty(),
                        unread = thread?.unread ?: 0,
                    )
                },
                onOpenGroup = { navController.navigate(Route.conversation(MillygramSession.groupThreadKey(it.groupId))) },
                onCreateGroup = { navController.navigate(Route.CREATE_GROUP) },
                onOpenConversation = { navController.navigate(Route.conversation(it.aci)) },
                onSettings = { navController.navigate(Route.SETTINGS) },
                // A handle typed into the search field has never been seen
                // before, so the send has to resolve it before there is a
                // conversation to open. Nothing navigates on success: the new
                // conversation simply appears in the list underneath, and the
                // row offering to start it stops matching once it does.
                onStartWithUsername = { username ->
                    scope.launch {
                        startError = null
                        starting = true
                        model.send(username, "Salom!")
                            // Silently dropping this left the row doing nothing
                            // at all for the commonest mistake there is: a
                            // mistyped handle.
                            .onFailure { startError = model.explain(it) }
                        starting = false
                    }
                },
                startError = startError,
                starting = starting,
            )
        }

        composable(Route.CONVERSATION) { entry ->
            val aci = entry.arguments?.getString("aci").orEmpty()
            val conversation = conversations.firstOrNull { it.aci == aci }

            // Opening it means it has been seen. Keyed on the message count as
            // well as the account, so a message that lands while this screen is
            // open is cleared too rather than lighting the row up the moment
            // the user steps back to the list.
            LaunchedEffect(aci, conversation?.messages?.size) {
                DeliveryService.clearNotification(context, aci)
                session.markRead(aci)
            }

            // The thread key doubles as the route argument, so this one screen
            // serves both kinds. What changes is where a reply goes, and that
            // must be decided here rather than inside the screen: sending a
            // group body to a thread key would deliver it to nobody.
            val groupId = MillygramSession.groupIdOf(aci)

            ConversationScreen(
                peerAci = aci,
                peerName = conversation?.username ?: groupId?.take(8) ?: aci.take(8),
                timeline = conversation.toTimeline(),
                onBack = { navController.popBackStack() },
                peerAvatarSeed = conversation?.avatarSeed ?: session.avatarSeed(aci),
                peerAvatarEmoji = conversation?.avatarEmoji ?: session.avatarEmoji(aci),
                onOpenProfile = {
                    if (groupId != null) navController.navigate(Route.groupDetail(groupId))
                    else navController.navigate(Route.safety(aci))
                },
                // A failure leaves the message on screen marked failed and
                // retryable, so nothing is lost if this throws.
                onSend = { body ->
                    scope.launch {
                        if (groupId != null) model.sendToGroup(groupId, body) else model.send(aci, body)
                    }
                },
                onRetry = { id -> scope.launch { model.retry(aci, id) } },
                identityChanged = aci in identityWarnings,
            )
        }

        composable(Route.CREATE_GROUP) {
            var busy by remember { mutableStateOf(false) }
            var failure by remember { mutableStateOf<String?>(null) }

            CreateGroupScreen(
                // Only people this device has keys for. A group is announced by
                // sending the roster to each member, so somebody never spoken
                // to has nowhere to receive it.
                contacts = conversations.filter { it.groupId == null }.map { it.toUi() },
                busy = busy,
                error = failure,
                onBack = { navController.popBackStack() },
                onCreate = { name, members ->
                    scope.launch {
                        busy = true
                        failure = null
                        model.createGroup(name, members)
                            .onSuccess { groupId ->
                                // Straight into the group, replacing this screen
                                // so Back returns to the list rather than to a
                                // form for a group that now exists.
                                navController.popBackStack()
                                navController.navigate(
                                    Route.conversation(MillygramSession.groupThreadKey(groupId)),
                                )
                            }
                            .onFailure { failure = model.explain(it) }
                        busy = false
                    }
                },
            )
        }

        composable(Route.GROUP_DETAIL) { entry ->
            val groupId = entry.arguments?.getString("groupId").orEmpty()
            val summary = groups.firstOrNull { it.groupId == groupId }
            var busy by remember { mutableStateOf(false) }
            var failure by remember { mutableStateOf<String?>(null) }

            // Left the group from this screen, or from another device: there is
            // nothing left to show, so do not sit on a blank page.
            if (summary == null) {
                LaunchedEffect(groupId) { navController.popBackStack() }
                return@composable
            }

            val named = { aci: String ->
                conversations.firstOrNull { it.aci == aci }?.username ?: aci.take(8)
            }

            GroupDetailScreen(
                group = Group(summary.groupId, summary.name, summary.members),
                nameOf = named,
                candidates = conversations
                    .filter { it.groupId == null && it.aci !in summary.members }
                    .map { it.toUi() },
                busy = busy,
                error = failure,
                onBack = { navController.popBackStack() },
                onSetMembers = { members ->
                    scope.launch {
                        busy = true
                        failure = null
                        model.setGroupMembers(groupId, members).onFailure { failure = model.explain(it) }
                        busy = false
                    }
                },
                onLeave = {
                    scope.launch {
                        busy = true
                        model.leaveGroup(groupId)
                            .onSuccess { navController.popBackStack(Route.CHATS, inclusive = false) }
                            .onFailure { failure = model.explain(it) }
                        busy = false
                    }
                },
            )
        }

        composable(Route.SETTINGS) {
            val ctx = androidx.compose.ui.platform.LocalContext.current
            val unlockAvailability = remember { AppLock.availability(ctx) }
            val posture = remember { session.securityPosture() }
            // Same source as the gate itself, so the two can never disagree.
            val requireUnlock by session.requireUnlockState.collectAsStateWithLifecycle()

            SettingsScreen(
                account = session.toAccount(
                    screenLock,
                    notificationDetail,
                    unlockAvailability,
                    requireUnlock,
                    posture,
                ),
                onToggleRequireUnlock = { wanted -> session.requireUnlock = wanted },
                onBack = { navController.popBackStack() },
                onToggleScreenLock = {
                    screenLock = it
                    onScreenSecurityChanged(it)
                },
                onBackup = { navController.navigate(Route.BACKUP) },
                onRecoveryNumber = { navController.navigate(Route.RECOVERY_NUMBER) },
                onLock = {
                    navController.popBackStack(Route.CHATS, inclusive = false)
                    model.lock()
                },
                onCycleNotificationDetail = {
                    val order = NotificationDetail.entries
                    val next = order[(order.indexOf(session.notificationDetail) + 1) % order.size]
                    session.notificationDetail = next
                    notificationDetail = next
                },
            )
        }

        composable(Route.RECOVERY_NUMBER) {
            var busy by remember { mutableStateOf(false) }
            var failure by remember { mutableStateOf<String?>(null) }
            // Read once per visit rather than observed: it only changes from
            // this screen, and re-reading the vault on every recomposition to
            // watch for a change nobody else can make would be work for
            // nothing.
            var attached by remember { mutableStateOf(session.recoveryNumber) }
            val scope = rememberCoroutineScope()

            RecoveryNumberScreen(
                current = attached,
                busy = busy,
                error = failure,
                onBack = { navController.popBackStack() },
                onAttach = { number ->
                    busy = true
                    failure = null
                    scope.launch {
                        runCatching { session.attachRecoveryNumber(number) }
                            .onSuccess {
                                attached = number
                                navController.popBackStack()
                            }
                            .onFailure { failure = model.explain(it) }
                        busy = false
                    }
                },
                onDetach = {
                    busy = true
                    failure = null
                    scope.launch {
                        runCatching { session.detachRecoveryNumber() }
                            .onSuccess {
                                attached = null
                                navController.popBackStack()
                            }
                            .onFailure { failure = model.explain(it) }
                        busy = false
                    }
                },
            )
        }

        composable(Route.BACKUP) {
            var busy by remember { mutableStateOf(false) }
            var failure by remember { mutableStateOf<String?>(null) }
            var pending by remember { mutableStateOf<String?>(null) }

            // The user picks where it goes. Nothing is written anywhere until
            // they have, and nothing is uploaded at all.
            val save = rememberLauncherForActivityResult(
                ActivityResultContracts.CreateDocument("application/octet-stream"),
            ) { uri ->
                val passphrase = pending
                pending = null
                if (uri == null || passphrase == null) {
                    busy = false
                    return@rememberLauncherForActivityResult
                }
                scope.launch {
                    runCatching {
                        val blob = session.exportBackup(passphrase)
                        withContext(Dispatchers.IO) {
                            context.contentResolver.openOutputStream(uri)?.use { it.write(blob) }
                                ?: error("cannot write there")
                        }
                    }.onSuccess {
                        busy = false
                        navController.popBackStack()
                    }.onFailure {
                        busy = false
                        failure = "Saqlab boʻlmadi"
                    }
                }
            }

            BackupScreen(
                onBack = { navController.popBackStack() },
                busy = busy,
                error = failure,
                onSave = { passphrase ->
                    failure = null
                    busy = true
                    pending = passphrase
                    save.launch("millygram-${session.username}.backup")
                },
            )
        }

        composable(Route.AVATAR_EMOJI) { entry ->
            val aci = entry.arguments?.getString("aci").orEmpty()
            val conversation = conversations.firstOrNull { it.aci == aci }
            EmojiPickerScreen(
                peerName = conversation?.username ?: aci.take(8),
                selected = conversation?.avatarEmoji ?: session.avatarEmoji(aci),
                onPick = { id -> session.setAvatarEmoji(aci, id) },
                onBack = { navController.popBackStack() },
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
                    peerAvatarSeed = conversation?.avatarSeed ?: session.avatarSeed(aci),
                    peerAvatarEmoji = conversation?.avatarEmoji ?: session.avatarEmoji(aci),
                    onChangeAvatarEmoji = { navController.navigate(Route.avatarEmoji(aci)) },
                    safetyNumber = resolved,
                    verified = verified,
                    onBack = { navController.popBackStack() },
                    onMarkVerified = { verified = !verified },
                    identityChanged = aci in identityWarnings,
                    onAcceptNewKey = { scope.launch { session.acceptNewIdentity(aci) } },
                )
            }
        }
    }

    LaunchedEffect(Unit) { onScreenSecurityChanged(screenLock) }

    // A notification names the conversation it came from, so tapping one lands
    // in that conversation rather than merely opening the app.
    LaunchedEffect(openConversation) {
        openConversation?.let { navController.navigate(Route.conversation(it)) }
    }
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
        avatarSeed = avatarSeed,
        avatarEmoji = avatarEmoji,
        unread = unread,
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
                        author = message.author,
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

private fun MillygramSession.toAccount(
    screenLock: Boolean,
    detail: NotificationDetail,
    unlock: AppLock.Availability,
    requireUnlock: Boolean,
    posture: uz.millygram.client.MillygramClient.SecurityPosture,
) =
    uz.millygram.app.ui.Account(
        displayName = username,
        username = username,
        screenLock = screenLock,
        notificationDetail = when (detail) {
            NotificationDetail.NameAndMessage -> "Ism va xabar"
            NotificationDetail.NameOnly -> "Faqat ism"
            NotificationDetail.Nothing -> "Hech narsa"
        },
        recoveryNumber = recoveryNumber,
        language = "Oʻzbekcha (lotin)",
        theme = "Tizim",
        buildHash = BuildConfigHash,
        avatarSeed = ownAvatarSeed,
        requireUnlock = requireUnlock,
        unlockUnavailable = when (unlock) {
            AppLock.Availability.Ready -> null
            // Says which of the two it is, because the fix is different: one
            // is a trip to system settings, the other is a phone that cannot
            // do this at all.
            AppLock.Availability.NotEnrolled -> "Barmoq izi sozlanmagan"
            AppLock.Availability.Unsupported -> "Qurilma qoʻllab-quvvatlamaydi"
        },
        strongBox = posture.strongBox,
        strongBoxHardware = posture.strongBoxHardware,
        environment = posture.environment,
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
