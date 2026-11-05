package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SingleUseAuthorizationCodeAuthenticationProviderTests {
    private val clock = Clock.fixed(Instant.parse("2026-11-04T00:00:00Z"), ZoneOffset.UTC)
    private val principal = UsernamePasswordAuthenticationToken.authenticated("client-123", "n/a", emptyList())

    @Test
    fun secondRedemptionOfTheSameCodeFailsBeforeTheDelegateRuns() {
        val delegate = CountingProvider { UsernamePasswordAuthenticationToken.authenticated("subject", "n/a", emptyList()) }
        val provider = SingleUseAuthorizationCodeAuthenticationProvider(
            delegate,
            InMemoryClaims(),
            RecordingAuthorizationService(null),
            clock,
        )
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
        val provider = SingleUseAuthorizationCodeAuthenticationProvider(
            delegate,
            InMemoryClaims(),
            RecordingAuthorizationService(null),
            clock,
        )
        val token = codeToken("code-2")

        assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }
        provider.authenticate(token)

        assertEquals(2, delegate.calls)
    }

    @Test
    fun completedReuseInvalidatesThePreviouslyIssuedTokens() {
        val token = codeToken("code-3")
        val issued = issuedAuthorization(token.code)
        val service = RecordingAuthorizationService(issued)
        val provider = SingleUseAuthorizationCodeAuthenticationProvider(
            CountingProvider { UsernamePasswordAuthenticationToken.authenticated("subject", "n/a", emptyList()) },
            InMemoryClaims(),
            service,
            clock,
        )

        provider.authenticate(token)
        assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertTrue(service.saved?.refreshToken?.isInvalidated == true)
    }

    private fun codeToken(code: String): OAuth2AuthorizationCodeAuthenticationToken =
        OAuth2AuthorizationCodeAuthenticationToken(code, principal, "http://127.0.0.1:8080/callback", emptyMap())

    private fun issuedAuthorization(code: String): OAuth2Authorization {
        val client = RegisteredClient.withId("client-id")
            .clientId("client-123")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://127.0.0.1:8080/callback")
            .scope("openid")
            .build()
        val now = Instant.now()
        val authorizationCode = OAuth2AuthorizationCode(code, now, now.plusSeconds(300))
        val access = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "access-" + code,
            now,
            now.plusSeconds(300),
            setOf("openid"),
        )
        val refresh = OAuth2RefreshToken("refresh-" + code, now, now.plusSeconds(3600))
        val authorization = OAuth2Authorization.withRegisteredClient(client)
            .id("authorization-" + code)
            .principalName("subject")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(setOf("openid"))
            .token(authorizationCode)
            .token(access)
            .token(refresh)
            .build()
        return OAuth2Authorization.from(authorization).invalidate(authorizationCode).build()
    }

    private class CountingProvider(private val result: (CountingProvider) -> Authentication) : AuthenticationProvider {
        var calls = 0
        override fun authenticate(authentication: Authentication): Authentication {
            calls += 1
            return result(this)
        }
        override fun supports(authentication: Class<*>): Boolean = true
    }

    private class RecordingAuthorizationService(private val authorization: OAuth2Authorization?) : OAuth2AuthorizationService {
        var saved: OAuth2Authorization? = null
        override fun save(authorization: OAuth2Authorization) {
            saved = authorization
        }
        override fun remove(authorization: OAuth2Authorization) = Unit
        override fun findById(id: String): OAuth2Authorization? = authorization?.takeIf { it.id == id }
        override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? = authorization
    }

    private class InMemoryClaims : CodeClaimStore {
        private val claims = mutableMapOf<String, CodeClaimResult>()
        override fun claim(code: String, expiresAt: Instant): CodeClaimResult =
            claims[code] ?: CodeClaimResult.CLAIMED.also { claims[code] = it }
        override fun complete(code: String) {
            if (claims[code] == CodeClaimResult.CLAIMED) claims[code] = CodeClaimResult.COMPLETED
        }
        override fun release(code: String) {
            claims.remove(code)
        }
    }
}
