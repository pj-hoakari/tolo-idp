package dev.usbharu.toloidp.security

import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import java.security.MessageDigest
import java.time.Clock

/** Authentication freshness is checked before tenant membership; the external UI performs login. */
class OidcAuthenticationRequestValidator(private val hintDecoder: JwtDecoder, private val clock: Clock) {
    fun validate(request: OAuth2AuthorizationCodeRequestAuthenticationToken, client: RegisteredClient): () -> Unit {
        val principal = request.principal as Authentication
        val oidc = "openid" in request.scopes.orEmpty()
        val parameters = request.additionalParameters
        fun parameter(name: String): String? = parameters[name]?.let {
            it as? String ?: reject("invalid_request", name)
        }
        if (oidc) {
            // JwtGenerator expects one String and otherwise fails only at code redemption.
            parameter("nonce")
            // Request Objects must never be silently replaced by the outer parameters.
            if (parameters.containsKey("request")) reject("request_not_supported", "request")
            if (parameters.containsKey("request_uri") ||
                (request as? TenantAuthorizationRequestToken)?.httpRequest?.parameterMap?.containsKey("request_uri") == true
            ) reject("request_uri_not_supported", "request_uri")
            parameter("response_mode")?.let {
                if (it != "query") reject("invalid_request", "response_mode")
            }
        }
        val prompt = if (oidc) parameter("prompt").orEmpty().split(' ').filter { it.isNotEmpty() }.toSet() else emptySet()
        if ("none" in prompt && prompt.size != 1) reject("invalid_request", "prompt")
        if (prompt.any { it !in setOf("none", "login", "consent", "select_account") }) {
            reject("invalid_request", "prompt")
        }
        val maxAge = if (oidc) parameter("max_age")?.let {
            if (!it.matches(Regex("[0-9]+"))) reject("invalid_request", "max_age")
            it.toLongOrNull() ?: reject("invalid_request", "max_age")
        } else null
        val hint = if (oidc) parameter("id_token_hint")?.let { decodeHint(it, client) } else null
        val authenticated = principal.isAuthenticated && principal !is AnonymousAuthenticationToken
        val now = clock.instant().epochSecond
        val authTime = authenticationTime(principal)
        val loginId = (principal.details as? Map<*, *>)?.get(LOGIN_ID) as? String
        val httpRequest = (request as? TenantAuthorizationRequestToken)?.httpRequest
        val fingerprint = httpRequest?.parameterMap?.toSortedMap()?.let { parameters ->
            buildString {
                append(parameters.size).append(';')
                parameters.forEach { (key, values) ->
                    append(key.length).append(':').append(key).append(values.size).append(';')
                    values.forEach { append(it.length).append(':').append(it) }
                }
            }
        }?.let { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).joinToString("") { byte -> "%02x".format(byte) } }
        val session = httpRequest?.getSession(false)
        val pending = session?.getAttribute(REAUTHENTICATION) as? Map<*, *>
        val challengedAt = pending?.get("created_at") as? Long
        val resumed = pending?.get("request") == fingerprint && fingerprint != null &&
            challengedAt != null && now >= challengedAt && now - challengedAt <= 300 &&
            loginId != null && loginId != pending?.get(LOGIN_ID) && authTime != null && authTime in challengedAt..now
        val stale = maxAge != null && maxAge > 0 && (authTime == null || authTime > now || now - authTime > maxAge)
        val forceLogin = "login" in prompt || maxAge == 0L
        if (!authenticated || (oidc && ((forceLogin && !resumed) || stale))) {
            // A single bounded challenge survives session-ID rotation by /api/login.
            if ("none" !in prompt && httpRequest != null && fingerprint != null &&
                (pending?.get("request") != fingerprint || challengedAt == null || now - challengedAt > 300)
            ) {
                httpRequest.getSession(true).setAttribute(REAUTHENTICATION, linkedMapOf(
                    "request" to fingerprint, LOGIN_ID to loginId.orEmpty(), "created_at" to now,
                ))
            }
            reject(if (oidc) "login_required" else "access_denied", "principal")
        }
        if (hint != null && hint.subject != principal.name) reject("login_required", "id_token_hint")
        // The external login UI supplies neither consent nor an account-selection proof.
        if ("consent" in prompt) reject("consent_required", "prompt")
        if ("select_account" in prompt) reject("account_selection_required", "prompt")
        return { if (resumed) session?.removeAttribute(REAUTHENTICATION) }
    }

    private fun decodeHint(value: String, client: RegisteredClient): Jwt {
        val hint = try { hintDecoder.decode(value) } catch (_: JwtException) { reject("invalid_request", "id_token_hint") }
        if (hint.subject.isNullOrBlank() || hint.issuedAt == null || hint.expiresAt == null ||
            client.clientId !in hint.audience || hint.hasClaim("token_use")
        ) reject("invalid_request", "id_token_hint")
        return hint
    }

    private fun reject(code: String, parameter: String): Nothing =
        throw OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error(code, "OAuth 2.0 Parameter: $parameter", null), null)

    companion object {
        const val AUTH_TIME = "auth_time"
        const val LOGIN_ID = "tolo_login_id"
        private const val REAUTHENTICATION = "tolo.oidc.reauthentication"

        fun authenticationTime(principal: Authentication): Long? =
            ((principal.details as? Map<*, *>)?.get(AUTH_TIME) as? String)?.toLongOrNull()
    }
}
