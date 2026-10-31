package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredWarn
import org.slf4j.LoggerFactory
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import tools.jackson.core.type.TypeReference
import tools.jackson.databind.ObjectMapper
import java.security.MessageDigest
import java.security.SecureRandom
import java.sql.Timestamp
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Base64

@Component
class LoginChallenges(
    private val jdbc: JdbcTemplate,
    private val json: ObjectMapper,
    private val clock: Clock,
) {
    fun issue(clientId: String, tenantId: String, parameters: Map<String, Array<String>>): String? {
        val request = json.writeValueAsString(parameters.mapValues { it.value.toList() })
        if (request.length > MAX_AUTHORIZATION_REQUEST_LENGTH) {
            log.structuredWarn(
                "Login challenge rejected",
                "event" to "login_challenge_rejected",
                "client_id" to clientId,
                "tenant_id" to tenantId,
                "failure_reason" to "authorization_request_too_large",
            )
            return null
        }
        val challenge = encoder.encodeToString(ByteArray(32).also(random::nextBytes))
        val now = clock.instant()
        jdbc.update("DELETE FROM idp_login_challenge WHERE expires_at <= ?", Timestamp.from(now))
        jdbc.update(
            "INSERT INTO idp_login_challenge (challenge_hash, tenant_id, authorization_request, expires_at) VALUES (?, ?, ?, ?)",
            hash(challenge), tenantId, request, Timestamp.from(now.plus(TTL)),
        )
        log.structuredInfo(
            "Login challenge issued",
            "event" to "login_challenge_issued",
            "challenge_id" to hash(challenge),
            "client_id" to clientId,
            "tenant_id" to tenantId,
        )
        return challenge
    }

    fun tenant(challenge: String): String? =
        jdbc.queryForList(
            "SELECT tenant_id FROM idp_login_challenge WHERE challenge_hash = ? AND login_id IS NULL AND expires_at > ?",
            String::class.java, hash(challenge), Timestamp.from(clock.instant()),
        ).singleOrNull()

    fun authenticate(challenge: String, loginId: String, subject: String): Boolean {
        val authenticated = jdbc.update(
            "UPDATE idp_login_challenge SET login_id = ? WHERE challenge_hash = ? AND login_id IS NULL AND expires_at > ?",
            loginId, hash(challenge), Timestamp.from(clock.instant()),
        ) == 1
        if (authenticated) {
            log.structuredInfo(
                "Login challenge authenticated",
                "event" to "login_challenge_authenticated",
                "challenge_id" to hash(challenge),
                "subject" to subject,
            )
        }
        return authenticated
    }

    fun consume(challenge: String, loginId: String?): Map<String, List<String>>? {
        val id = hash(challenge)
        val stored = jdbc.query(
            "SELECT authorization_request, login_id, expires_at FROM idp_login_challenge WHERE challenge_hash = ?",
            { rs, _ -> Stored(rs.getString(1), rs.getString(2), rs.getTimestamp(3).toInstant()) },
            id,
        ).singleOrNull()
        val failure = when {
            stored == null -> "unknown"
            !stored.expiresAt.isAfter(clock.instant()) -> "expired"
            stored.loginId == null -> "not_authenticated"
            stored.loginId != loginId -> "login_mismatch"
            jdbc.update("DELETE FROM idp_login_challenge WHERE challenge_hash = ? AND login_id = ?", id, loginId) != 1 -> "consumed"
            else -> null
        }
        if (failure != null) {
            log.structuredWarn(
                "Login challenge rejected",
                "event" to "login_challenge_rejected",
                "challenge_id" to id,
                "failure_reason" to failure,
            )
            return null
        }
        log.structuredInfo("Login challenge consumed", "event" to "login_challenge_consumed", "challenge_id" to id)
        return json.readValue(stored!!.request, PARAMETERS)
    }

    private fun hash(challenge: String): String =
        encoder.encodeToString(MessageDigest.getInstance("SHA-256").digest(challenge.toByteArray()))

    private data class Stored(val request: String, val loginId: String?, val expiresAt: Instant)

    companion object {
        private val log = LoggerFactory.getLogger(LoginChallenges::class.java)
        private val TTL = Duration.ofMinutes(10)
        private const val MAX_AUTHORIZATION_REQUEST_LENGTH = 8 * 1024
        private val random = SecureRandom()
        private val encoder = Base64.getUrlEncoder().withoutPadding()
        private val PARAMETERS = object : TypeReference<Map<String, List<String>>>() {}
    }
}
