package uz.millygram.app.data

import uz.millygram.client.TransportError

/**
 * Turning a failure into something a person can act on.
 *
 * Extracted from the view model so it can be tested. It is a pure function of
 * the failure and touches nothing else, which is what made it worth moving:
 * the view model needs an Application to construct, and this needed none of it.
 */
internal fun describeGatewayFailure(failure: Throwable): String {
    val message = failure.message.orEmpty()
    return when {
            "username_taken" in message -> "Bu nom band"
            // First come, first served. The gateway will not move a number off
            // the account holding it, because nothing here proves who owns it.
            "number_in_use" in message ->
                "Bu raqam boshqa hisobga ulangan. Uni koʻchirib boʻlmaydi"
            "not_found" in message -> "Bunday foydalanuvchi topilmadi"
            "slow_down" in message -> "Juda koʻp urinish. Biroz kuting"
            // The device clock, not the server's: registration is refused if
            // they differ by more than five minutes, and a handset that has
            // been flat for a while comes back with the wrong time.
            "clock_skew" in message -> "Qurilma soati notoʻgʻri. Sana va vaqtni tekshiring"
            "work_required" in message -> "Server band. Biroz kutib, qayta urinib koʻring"
            // A refusal the gateway put into words is not a connection failure,
            // and has to be split out before the branch below.
            //
            // TransportError extends IOException, so without this an HTTP 400
            // the server explained in detail reads as a server that could not
            // be reached — which sends whoever is debugging it to DNS, TLS and
            // the network, where nothing is wrong. That is not hypothetical: it
            // cost an hour against a gateway answering `invalid_request`
            // because its schema had moved on, while the phone could reach it
            // in under a second.
            //
            // The code is shown rather than swallowed. The codes above are the
            // ones worth translating; the rest are rare enough that naming them
            // is more use than a sentence that fits every failure equally.
            failure is TransportError -> "Server soʻrovni rad etdi (${failure.code})"

            "Failed to connect" in message ||
                "Unable to resolve" in message ||
                "timeout" in message.lowercase() ||
                failure is java.io.IOException -> "Serverga ulanib boʻlmadi"
            else -> "Xatolik yuz berdi. Qayta urinib koʻring"
        }
}
