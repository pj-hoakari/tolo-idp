package dev.usbharu.toloidp.security

import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.JdbcOperations
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate

interface RefreshRevocationAware {
    fun saveRefreshRevocation(authorization: OAuth2Authorization)
    fun saveAccessRevocation(authorization: OAuth2Authorization)
}

/**
 * Serializes refresh-token state changes on the authorization row. A normal save after
 * a completed refresh revocation is rejected; revocation entry points re-read the
 * current row under the same lock so a stale snapshot cannot overwrite a rotation.
 */
class RefreshAwareOAuth2AuthorizationService(
    jdbcOperations: JdbcOperations,
    registeredClientRepository: RegisteredClientRepository,
    private val stateStore: RefreshStateStore,
    transactionManager: PlatformTransactionManager,
) : JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository), RefreshRevocationAware {
    private val transactions = TransactionTemplate(transactionManager)

    override fun save(authorization: OAuth2Authorization) {
        val id = authorization.id ?: run {
            super.save(authorization)
            return
        }
        transactions.executeWithoutResult {
            if (lockRefreshState(id) == true) {
                throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
            }
            super.save(authorization)
        }
    }

    override fun saveRefreshRevocation(authorization: OAuth2Authorization) {
        val id = authorization.id ?: return
        val target = authorization.refreshToken?.token?.tokenValue ?: return
        transactions.executeWithoutResult {
            if (lockRefreshState(id) != false) return@executeWithoutResult
            val current = super.findById(id) ?: return@executeWithoutResult
            val currentRefresh = current.refreshToken?.token ?: return@executeWithoutResult
            if (currentRefresh.tokenValue != target) return@executeWithoutResult
            stateStore.markRefreshRevoked(id)
            super.save(OAuth2Authorization.from(current).invalidate(currentRefresh).build())
        }
    }

    override fun saveAccessRevocation(authorization: OAuth2Authorization) {
        val id = authorization.id ?: return
        val target = authorization.accessToken?.token?.tokenValue ?: return
        transactions.executeWithoutResult {
            // Lock the same row so a concurrent refresh cannot rotate the access token
            // between the read and the invalidation. Access revocation is allowed after
            // refresh revocation.
            if (lockRefreshState(id) == null) return@executeWithoutResult
            val current = super.findById(id) ?: return@executeWithoutResult
            val currentAccess = current.accessToken?.token ?: return@executeWithoutResult
            if (currentAccess.tokenValue != target) return@executeWithoutResult
            super.save(OAuth2Authorization.from(current).invalidate(currentAccess).build())
        }
    }

    private fun lockRefreshState(id: String): Boolean? =
        try {
            stateStore.lockRefreshRevoked(id)
        } catch (_: EmptyResultDataAccessException) {
            null
        }
}
