package dev.usbharu.toloidp.security

import org.springframework.dao.DuplicateKeyException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.util.Base64

interface CodeClaimStore {
    fun claim(code: String, expiresAt: Instant): Boolean
    fun release(code: String)
}

/** Database-backed one-time claim for authorization-code redemption. */
@Component
class JdbcCodeClaimStore(
    private val jdbc: JdbcTemplate,
    private val clock: Clock,
) : CodeClaimStore {
    override fun claim(code: String, expiresAt: Instant): Boolean {
        val now = clock.instant()
        jdbc.update("DELETE FROM idp_authorization_code_claim WHERE expires_at <= ?", Timestamp.from(now))
        return try {
            jdbc.update(
                "INSERT INTO idp_authorization_code_claim (code_hash, expires_at) VALUES (?, ?)",
                hash(code),
                Timestamp.from(expiresAt),
            ) == 1
        } catch (_: DuplicateKeyException) {
            false
        }
    }

    override fun release(code: String) {
        jdbc.update("DELETE FROM idp_authorization_code_claim WHERE code_hash = ?", hash(code))
    }

    private fun hash(code: String): String =
        Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(code.toByteArray()))
}
