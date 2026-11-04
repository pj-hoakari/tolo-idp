package dev.usbharu.toloidp.security

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken
import java.time.Clock
import java.time.Duration

/**
 * Claims an authorization code in the database before the framework provider reads it.
 * Concurrent or repeated redemptions lose the claim and receive invalid_grant.
 */
class SingleUseAuthorizationCodeAuthenticationProvider(
    private val delegate: AuthenticationProvider,
    private val claims: CodeClaimStore,
    private val clock: Clock,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication? {
        val token = authentication as OAuth2AuthorizationCodeAuthenticationToken
        val code = token.code
        if (!claims.claim(code, clock.instant().plus(CLAIM_TTL))) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
        return try {
            delegate.authenticate(authentication).also {
                if (it == null) claims.release(code)
            }
        } catch (ex: AuthenticationException) {
            claims.release(code)
            throw ex
        } catch (ex: RuntimeException) {
            claims.release(code)
            throw ex
        }
    }

    override fun supports(authentication: Class<*>): Boolean = delegate.supports(authentication)

    companion object {
        private val CLAIM_TTL: Duration = Duration.ofMinutes(15)
    }
}
