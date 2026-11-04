package dev.usbharu.toloidp.security

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider
import java.time.Clock
import java.time.Duration

/**
 * Claims an authorization code in the database before the framework provider reads it.
 * Concurrent or repeated redemptions lose the claim. A completed reuse also performs
 * the same previously-issued-token invalidation as the framework provider.
 */
class SingleUseAuthorizationCodeAuthenticationProvider(
    private val delegate: AuthenticationProvider,
    private val claims: CodeClaimStore,
    private val authorizationService: OAuth2AuthorizationService,
    private val clock: Clock,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication? {
        val token = authentication as OAuth2AuthorizationCodeAuthenticationToken
        val code = token.code
        return when (claims.claim(code, clock.instant().plus(CLAIM_TTL))) {
            CodeClaimResult.CLAIMED -> try {
                delegate.authenticate(authentication).also { result ->
                    if (result == null) {
                        claims.release(code)
                    } else {
                        claims.complete(code)
                    }
                }
            } catch (ex: AuthenticationException) {
                claims.release(code)
                throw ex
            } catch (ex: RuntimeException) {
                claims.release(code)
                throw ex
            }
            CodeClaimResult.COMPLETED -> {
                invalidatePreviouslyIssuedTokens(code)
                throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
            }
            CodeClaimResult.IN_PROGRESS -> throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
    }

    override fun supports(authentication: Class<*>): Boolean = delegate.supports(authentication)

    private fun invalidatePreviouslyIssuedTokens(code: String) {
        val authorization = authorizationService.findByToken(code, AUTHORIZATION_CODE_TOKEN_TYPE) ?: return
        val codeToken = authorization.getToken(OAuth2AuthorizationCode::class.java) ?: return
        if (!codeToken.isInvalidated) return
        val token = authorization.refreshToken ?: authorization.accessToken ?: return
        try {
            authorizationService.save(OAuth2Authorization.from(authorization).invalidate(token.token).build())
        } catch (_: OAuth2AuthenticationException) {
            // The tokens are already invalid; a revocation guard may reject the save.
        }
    }

    companion object {
        private val CLAIM_TTL: Duration = Duration.ofMinutes(15)
        private val AUTHORIZATION_CODE_TOKEN_TYPE = OAuth2TokenType(OAuth2ParameterNames.CODE)
    }
}
