package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SingleUseAuthorizationCodeAuthenticationProviderTests {
    private val clock = Clock.fixed(Instant.parse("2026-11-04T00:00:00Z"), ZoneOffset.UTC)
    private val principal = UsernamePasswordAuthenticationToken.authenticated("client-123", "n/a", emptyList())

    @Test
    fun secondRedemptionOfTheSameCodeFailsBeforeTheDelegateRuns() {
        val delegate = CountingProvider { UsernamePasswordAuthenticationToken.authenticated("subject", "n/a", emptyList()) }
        val provider = SingleUseAuthorizationCodeAuthenticationProvider(delegate, InMemoryClaims(), clock)
        val token = codeToken("code-1")

        provider.authenticate(token)
        val error = assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertEquals("invalid_grant", error.error.errorCode)
        assertEquals(1, delegate.calls)
    }

    @Test
    fun delegateFailureReleasesTheClaimForARetry() {
        val delegate = CountingProvider {
            if (it.calls == 1) throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
            UsernamePasswordAuthenticationToken.authenticated("subject", "n/a", emptyList())
        }
        val provider = SingleUseAuthorizationCodeAuthenticationProvider(delegate, InMemoryClaims(), clock)
        val token = codeToken("code-2")

        assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }
        provider.authenticate(token)

        assertEquals(2, delegate.calls)
    }

    private fun codeToken(code: String): OAuth2AuthorizationCodeAuthenticationToken =
        OAuth2AuthorizationCodeAuthenticationToken(code, principal, "http://127.0.0.1:8080/callback", emptyMap())

    private class CountingProvider(private val result: (CountingProvider) -> Authentication) : AuthenticationProvider {
        var calls = 0
        override fun authenticate(authentication: Authentication): Authentication {
            calls += 1
            return result(this)
        }
        override fun supports(authentication: Class<*>): Boolean = true
    }

    private class InMemoryClaims : CodeClaimStore {
        private val claims = mutableSetOf<String>()
        override fun claim(code: String, expiresAt: Instant): Boolean = claims.add(code)
        override fun release(code: String) {
            claims.remove(code)
        }
    }
}
