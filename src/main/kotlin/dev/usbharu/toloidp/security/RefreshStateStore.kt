package dev.usbharu.toloidp.security

import org.springframework.dao.DuplicateKeyException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.TransactionDefinition
import org.springframework.transaction.support.TransactionTemplate

interface RefreshStateStore {
    /** Ensure the state row exists and lock it; returns whether refresh was already revoked. */
    fun lockRefreshRevoked(authorizationId: String): Boolean

    /** Ensure the state row exists, lock it, and mark refresh as revoked. */
    fun lockAndRevokeRefresh(authorizationId: String)
}

@Component
class JdbcRefreshStateStore(
    private val jdbc: JdbcTemplate,
    transactionManager: PlatformTransactionManager,
) : RefreshStateStore {
    private val newTransaction = TransactionTemplate(transactionManager).apply {
        propagationBehavior = TransactionDefinition.PROPAGATION_REQUIRES_NEW
    }

    override fun lockRefreshRevoked(authorizationId: String): Boolean {
        ensureRow(authorizationId)
        return jdbc.queryForObject(
            "SELECT refresh_revoked FROM idp_authorization_refresh_state WHERE authorization_id = ? FOR UPDATE",
            Boolean::class.java,
            authorizationId,
        ) == true
    }

    override fun lockAndRevokeRefresh(authorizationId: String) {
        ensureRow(authorizationId)
        jdbc.update(
            "UPDATE idp_authorization_refresh_state SET refresh_revoked = true WHERE authorization_id = ?",
            authorizationId,
        )
    }

    private fun ensureRow(authorizationId: String) {
        try {
            newTransaction.executeWithoutResult {
                jdbc.update(
                    "INSERT INTO idp_authorization_refresh_state (authorization_id, refresh_revoked) VALUES (?, false)",
                    authorizationId,
                )
            }
        } catch (_: DuplicateKeyException) {
            // Another request created the row first. The duplicate statement was
            // rolled back in its own transaction; the row is now visible to the caller.
        }
    }
}
