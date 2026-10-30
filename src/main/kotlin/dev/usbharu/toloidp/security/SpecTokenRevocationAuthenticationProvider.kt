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
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken
import java.time.Clock
import java.time.Instant

/**
 * RFC 7009 に従い Refresh Token を無効化し、JWT access token を jti denylist に登録する。
 */
class SpecTokenRevocationAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val jtiDenylistRepository: JtiDenylistRepository,
    private val auditService: AuditService,
    private val clock: Clock,
    private val jwtDecoder: JwtDecoder,
    private val issuer: String,
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
            val policy = ClientPolicy.from(registeredClient)
                ?: fail(OAuth2ErrorCodes.INVALID_CLIENT, "client_not_allowed")
            if (policy.clientType != ClientType.CONFIDENTIAL ||
                clientPrincipal.clientAuthenticationMethod == ClientAuthenticationMethod.NONE
            ) {
                fail(OAuth2ErrorCodes.INVALID_CLIENT, "client_not_allowed")
            }

            val preferredType = if (tokenTypeHint == OAuth2ParameterNames.REFRESH_TOKEN) {
                OAuth2TokenType.REFRESH_TOKEN
            } else {
                OAuth2TokenType.ACCESS_TOKEN
            }
            val fallbackType = if (preferredType == OAuth2TokenType.ACCESS_TOKEN) {
                OAuth2TokenType.REFRESH_TOKEN
            } else {
                OAuth2TokenType.ACCESS_TOKEN
            }
            // hint は検索順の指定であり、別の対応済み token 種別への検索を省略しない。
            val authorization = authorizationService.findByToken(revocation.token, preferredType)
                ?: authorizationService.findByToken(revocation.token, fallbackType)
                ?: return revokeUnstoredJwt(revocation, registeredClient.clientId, audit)
            if (authorization.registeredClientId != registeredClient.id) {
                fail(OAuth2ErrorCodes.INVALID_CLIENT, "subject_token_client_mismatch")
            }

            val refreshToken = authorization.refreshToken?.takeIf { it.token.tokenValue == revocation.token }
            val accessToken = if (refreshToken != null) {
                authorization.accessToken
            } else {
                authorization.getToken<OAuth2AccessToken>(revocation.token)
            } ?: fail(OAuth2ErrorCodes.INVALID_REQUEST, "token_not_access_token")
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
            val builder = OAuth2Authorization.from(authorization)
            if (refreshToken != null) {
                // Spring の invalidate は同じ authorization の access token も無効化する。
                builder.invalidate(refreshToken.token)
            } else {
                builder.invalidate(accessToken.token)
            }
            authorizationService.save(builder.build())

            return success(
                revocation,
                audit.copy(
                    subject = claims["sub"] as? String ?: authorization.principalName,
                    sourceTokenUse = if (refreshToken != null) OAuth2ParameterNames.REFRESH_TOKEN else tokenUse,
                    requestedResource = claims["resource"] as? String,
                    requestedScope = if (refreshToken != null) authorization.authorizedScopes.toList() else scopeList(claims["scope"]),
                    tenantId = claims["tenant_id"] as? String,
                    eventId = claims["event_id"] as? String,
                    issuedJti = if (refreshToken != null) null else jti,
                ),
            )
        } catch (ex: SpecRevocationFailure) {
            auditService.record(audit.copy(result = "failure", failureReason = ex.failureReason))
            throw OAuth2AuthenticationException(OAuth2Error(ex.errorCode))
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2TokenRevocationAuthenticationToken::class.java.isAssignableFrom(authentication)

    /** A refresh replaces JDBC's current token, but the older signed JWT can still be revoked. */
    private fun revokeUnstoredJwt(
        revocation: OAuth2TokenRevocationAuthenticationToken, clientId: String, audit: TokenAuditEvent,
    ): Authentication {
        val jwt = try { jwtDecoder.decode(revocation.token) } catch (_: JwtException) { return success(revocation, audit) }
        val tokenUse = jwt.getClaimAsString("token_use")
        val expiresAt = jwt.expiresAt
        val jti = jwt.id
        val now = clock.instant()
        if (jwt.issuer?.toString() != issuer || tokenUse !in setOf(TOKEN_USE_TENANT_ACCESS, TOKEN_USE_EVENT_ACCESS) ||
            jti.isNullOrBlank() || expiresAt == null || !expiresAt.isAfter(now) || jwt.notBefore?.isAfter(now) == true
        ) return success(revocation, audit)
        if (jwt.getClaimAsString("client_id") != clientId) {
            fail(OAuth2ErrorCodes.INVALID_CLIENT, "subject_token_client_mismatch")
        }
        saveDenylistEntry(jti, expiresAt)
        return success(revocation, audit.copy(
            subject = jwt.subject, sourceTokenUse = tokenUse, requestedResource = jwt.getClaimAsString("resource"),
            requestedScope = scopeList(jwt.claims["scope"]), tenantId = jwt.getClaimAsString("tenant_id"),
            eventId = jwt.getClaimAsString("event_id"), issuedJti = jti,
        ))
    }

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
