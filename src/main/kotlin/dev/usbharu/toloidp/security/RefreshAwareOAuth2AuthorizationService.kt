package dev.usbharu.toloidp.security

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
}

/**
 * Serializes refresh-token state changes per authorization row. A normal save after a
 * completed refresh revocation is rejected; the revocation save itself uses the
 * non-checking entry point.
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
            if (stateStore.lockRefreshRevoked(id)) {
                throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
            }
            super.save(authorization)
        }
    }

    override fun saveRefreshRevocation(authorization: OAuth2Authorization) {
        val id = authorization.id ?: run {
            save(authorization)
            return
        }
        transactions.executeWithoutResult {
            stateStore.lockAndRevokeRefresh(id)
            super.save(authorization)
        }
    }
}
