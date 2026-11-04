package dev.usbharu.toloidp.security

import org.springframework.dao.DuplicateKeyException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.util.Base64

enum class CodeClaimResult {
    CLAIMED,
    IN_PROGRESS,
    COMPLETED,
}

interface CodeClaimStore {
    fun claim(code: String, expiresAt: Instant): CodeClaimResult
    fun complete(code: String)
    fun release(code: String)
}

/** Database-backed one-time claim for authorization-code redemption. */
@Component
class JdbcCodeClaimStore(
    private val jdbc: JdbcTemplate,
    private val clock: Clock,
) : CodeClaimStore {
    override fun claim(code: String, expiresAt: Instant): CodeClaimResult {
        val now = clock.instant()
        jdbc.update("DELETE FROM idp_authorization_code_claim WHERE expires_at <= ?", Timestamp.from(now))
        return try {
            jdbc.update(
                "INSERT INTO idp_authorization_code_claim (code_hash, expires_at, completed) VALUES (?, ?, false)",
                hash(code),
                Timestamp.from(expiresAt),
            )
            CodeClaimResult.CLAIMED
        } catch (_: DuplicateKeyException) {
            try {
                val completed = jdbc.queryForObject(
                    "SELECT completed FROM idp_authorization_code_claim WHERE code_hash = ?",
                    Boolean::class.java,
                    hash(code),
                ) == true
                if (completed) CodeClaimResult.COMPLETED else CodeClaimResult.IN_PROGRESS
            } catch (_: EmptyResultDataAccessException) {
                CodeClaimResult.IN_PROGRESS
            }
        }
    }

    override fun complete(code: String) {
        jdbc.update(
            "UPDATE idp_authorization_code_claim SET completed = true WHERE code_hash = ?",
            hash(code),
        )
    }

    override fun release(code: String) {
        jdbc.update("DELETE FROM idp_authorization_code_claim WHERE code_hash = ?", hash(code))
    }

    private fun hash(code: String): String =
        Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(code.toByteArray()))
}
