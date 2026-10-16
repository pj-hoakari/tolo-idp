package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientType
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken
import java.time.Clock
import java.time.Instant

/**
 * RFC 7009 の revocation request を、JWT access token の jti denylist 登録として処理する。
 */
class SpecTokenRevocationAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val jtiDenylistRepository: JtiDenylistRepository,
    private val auditService: AuditService,
    private val clock: Clock,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val revocation = authentication as OAuth2TokenRevocationAuthenticationToken
        val clientPrincipal = authenticatedClient(revocation)
        val registeredClient = clientPrincipal.registeredClient ?: fail("invalid_client", "client_not_authenticated")
        val audit = TokenAuditEvent(
            clientId = registeredClient.clientId,
            requestedTokenUse = "revocation",
            result = "success",
        )

        try {
            val tokenTypeHint = revocation.tokenTypeHint
            if (tokenTypeHint != null && tokenTypeHint != OAuth2ParameterNames.ACCESS_TOKEN) {
                fail(OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE, "unsupported_token_type")
            }

            val policy = ClientPolicy.from(registeredClient)
                ?: fail(OAuth2ErrorCodes.INVALID_CLIENT, "client_not_allowed")
            if (policy.clientType != ClientType.CONFIDENTIAL ||
                clientPrincipal.clientAuthenticationMethod == ClientAuthenticationMethod.NONE
            ) {
                fail(OAuth2ErrorCodes.INVALID_CLIENT, "client_not_allowed")
            }

            val authorization = authorizationService.findByToken(revocation.token, OAuth2TokenType.ACCESS_TOKEN)
                ?: return success(revocation, audit)
            if (authorization.registeredClientId != registeredClient.id) {
                fail(OAuth2ErrorCodes.INVALID_CLIENT, "subject_token_client_mismatch")
            }

            val accessToken = authorization.getToken<OAuth2AccessToken>(revocation.token)
                ?: fail(OAuth2ErrorCodes.INVALID_REQUEST, "token_not_access_token")
            val claims = accessToken.claims
                ?: fail(OAuth2ErrorCodes.INVALID_REQUEST, "token_invalid_claims")
            val jti = claims["jti"] as? String
                ?: fail(OAuth2ErrorCodes.INVALID_REQUEST, "token_invalid_claims")
            val expiresAt = claimInstant(claims["exp"])
                ?: accessToken.token.expiresAt
                ?: fail(OAuth2ErrorCodes.INVALID_REQUEST, "token_invalid_claims")

            val tokenUse = claims["token_use"] as? String
            if (tokenUse != TOKEN_USE_TENANT_ACCESS && tokenUse != TOKEN_USE_EVENT_ACCESS) {
                fail(OAuth2ErrorCodes.INVALID_REQUEST, "token_invalid_claims")
            }

            val now = Instant.now(clock)
            if (expiresAt.isAfter(now)) {
                saveDenylistEntry(jti, expiresAt)
            }
            authorizationService.save(OAuth2Authorization.from(authorization).invalidate(accessToken.token).build())

            return success(
                revocation,
                audit.copy(
                    subject = claims["sub"] as? String ?: authorization.principalName,
                    sourceTokenUse = tokenUse,
                    requestedResource = claims["resource"] as? String,
                    requestedScope = scopeList(claims["scope"]),
                    tenantId = claims["tenant_id"] as? String,
                    eventId = claims["event_id"] as? String,
                    issuedJti = jti,
                ),
            )
        } catch (ex: SpecRevocationFailure) {
            auditService.record(audit.copy(result = "failure", failureReason = ex.failureReason))
            throw OAuth2AuthenticationException(OAuth2Error(ex.errorCode))
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2TokenRevocationAuthenticationToken::class.java.isAssignableFrom(authentication)

    private fun authenticatedClient(revocation: OAuth2TokenRevocationAuthenticationToken): OAuth2ClientAuthenticationToken {
        val clientPrincipal = revocation.principal as? OAuth2ClientAuthenticationToken
            ?: throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT))
        if (!clientPrincipal.isAuthenticated || clientPrincipal.registeredClient == null) {
            throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT))
        }
        return clientPrincipal
    }

    private fun success(
        revocation: OAuth2TokenRevocationAuthenticationToken,
        audit: TokenAuditEvent,
    ): OAuth2TokenRevocationAuthenticationToken {
        auditService.record(audit)
        return OAuth2TokenRevocationAuthenticationToken(
            SimpleRevokedToken(revocation.token, Instant.now(clock)),
            revocation.principal as Authentication,
        )
    }

    private fun saveDenylistEntry(jti: String, expiresAt: Instant) {
        if (jtiDenylistRepository.existsById(jti)) {
            return
        }
        try {
            jtiDenylistRepository.save(
                JtiDenylistEntry(jti = jti, expiresAt = expiresAt)
                    .apply { isNewEntity = true },
            )
        } catch (ex: DataIntegrityViolationException) {
            // Concurrent revoke of the same token is idempotent.
        }
    }

    private fun claimInstant(value: Any?): Instant? =
        when (value) {
            is Instant -> value
            is Number -> Instant.ofEpochSecond(value.toLong())
            else -> null
        }

    private fun scopeList(value: Any?): List<String> =
        when (value) {
            is String -> value.split(" ").filter { it.isNotBlank() }
            is Collection<*> -> value.filterIsInstance<String>()
            else -> emptyList()
        }

    private fun fail(errorCode: String, failureReason: String): Nothing {
        throw SpecRevocationFailure(errorCode, failureReason)
    }

    private class SimpleRevokedToken(
        private val value: String,
        private val issuedAt: Instant,
    ) : OAuth2Token {
        override fun getTokenValue(): String = value

        override fun getIssuedAt(): Instant = issuedAt

        override fun getExpiresAt(): Instant = issuedAt
    }

    private class SpecRevocationFailure(
        val errorCode: String,
        val failureReason: String,
    ) : AuthenticationException(failureReason)
}
