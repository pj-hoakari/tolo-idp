package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.devicegrant.DeviceGrant
import dev.usbharu.toloidp.devicegrant.DeviceGrantRefreshOutcome
import dev.usbharu.toloidp.devicegrant.DeviceGrantRefreshStateException
import dev.usbharu.toloidp.devicegrant.DeviceGrantService
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.stubbing.Answer
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

@Tag("unit")
class SpecRefreshTokenAuthenticationProviderTests {
    private val grant = DeviceGrant(
        id = "authorization-1",
        tenantId = "tenant-a",
        eventId = "event-1",
        edgeDeviceId = "abcdefabcdefabcd",
        approverSubject = "user-1",
        clientId = "esp-camera",
        approvedAt = Instant.parse("2026-11-17T00:00:00Z"),
        absoluteExpiresAt = Instant.parse("2026-11-24T00:00:00Z"),
        createdAt = Instant.parse("2026-11-17T00:00:00Z"),
    )
    private val delegate = mock(OAuth2RefreshTokenAuthenticationProvider::class.java)
    private val client = RegisteredClient.withId("client-id")
        .clientId("esp-camera")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("events.stream")
        .build()
    private val clientPrincipal = OAuth2ClientAuthenticationToken(
        client,
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        null,
    )
    private val token = OAuth2RefreshTokenAuthenticationToken(
        "refresh-token",
        clientPrincipal,
        emptySet(),
        emptyMap(),
    )

    @Test
    fun unexpectedRefreshFailureRevokesTheGrantWhenItCanBeFound() {
        val service = service(grant)
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        val error = assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertEquals("server_error", error.error.errorCode)
        verify(service).requireCurrentRefreshScopes("refresh-token", client, emptySet())
        verify(service).revokeAfterFailedRefresh(grant)
    }

    @Test
    fun unexpectedRefreshFailureWithoutAGrantStillFailsClosed() {
        val service = service(grant = null)
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        val error = assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertEquals("server_error", error.error.errorCode)
        verify(service, never()).revokeAfterFailedRefresh(grant)
    }

    @Test
    fun lookupFailureDoesNotPreventTheRefreshFailureFromFailingClosed() {
        val service = service(lookupFailure = true)
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        val error = assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertEquals("server_error", error.error.errorCode)
        verify(service, never()).revokeAfterFailedRefresh(grant)
    }

    @Test
    fun refreshStateFailureRevokesTheGrantAndPropagatesTheOAuthError() {
        val service = service(
            grant = grant,
            refreshFailure = DeviceGrantRefreshStateException(
                grant,
                OAuth2AuthenticationException(OAuth2Error("invalid_grant")),
            ),
        )
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        val error = assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertEquals("invalid_grant", error.error.errorCode)
        verify(service).revokeAfterFailedRefresh(grant)
    }

    @Test
    fun nonCameraClientDelegatesToTheStandardProvider() {
        val otherClient = RegisteredClient.withId("other-id")
            .clientId("client-123")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .build()
        val otherPrincipal = OAuth2ClientAuthenticationToken(
            otherClient,
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
            null,
        )
        val otherToken = OAuth2RefreshTokenAuthenticationToken(
            "other-refresh-token",
            otherPrincipal,
            emptySet(),
            emptyMap(),
        )
        val expected = UsernamePasswordAuthenticationToken.authenticated("subject", null, emptyList())
        `when`(delegate.authenticate(otherToken)).thenReturn(expected)
        val service = service()
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        assertSame(expected, provider.authenticate(otherToken))
        verify(service, never()).findGrantByRefreshToken(anyString())
    }

    @Test
    fun issuedRefreshReturnsTheDelegateAuthentication() {
        val access = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "access-token",
            Instant.now(),
            Instant.now().plusSeconds(300),
            setOf("events.stream"),
        )
        val authentication = OAuth2AccessTokenAuthenticationToken(client, clientPrincipal, access)
        `when`(delegate.authenticate(token)).thenReturn(authentication)
        val service = service(invokeLambda = true)
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        assertSame(authentication, provider.authenticate(token))
    }

    @Test
    fun rejectedRefreshReturnsInvalidGrant() {
        val service = service(refreshOutcome = DeviceGrantRefreshOutcome.Rejected)
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        val error = assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertEquals("invalid_grant", error.error.errorCode)
    }

    @Test
    fun delegateWithoutAuthenticationFailsAsServerError() {
        val service = service(invokeLambda = true)
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service, "esp-camera")

        val error = assertFailsWith<OAuth2AuthenticationException> { provider.authenticate(token) }

        assertEquals("server_error", error.error.errorCode)
    }

    @Test
    fun supportsRefreshTokenAuthentication() {
        val provider = SpecRefreshTokenAuthenticationProvider(delegate, service(), "esp-camera")

        assertTrue(provider.supports(OAuth2RefreshTokenAuthenticationToken::class.java))
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken::class.java))
    }

    private fun service(
        grant: DeviceGrant? = this.grant,
        lookupFailure: Boolean = false,
        refreshFailure: Throwable = RuntimeException("commit failed"),
        refreshOutcome: DeviceGrantRefreshOutcome? = null,
        invokeLambda: Boolean = false,
    ): DeviceGrantService =
        mock(DeviceGrantService::class.java, Answer { invocation ->
            when (invocation.method.name) {
                "findGrantByRefreshToken" ->
                    if (lookupFailure) throw IllegalStateException("lookup failed") else grant
                "refresh" -> when {
                    refreshOutcome != null -> refreshOutcome
                    invokeLambda -> {
                        @Suppress("UNCHECKED_CAST")
                        val issueTokens = invocation.getArgument(2) as () -> OAuth2AccessTokenAuthenticationToken
                        DeviceGrantRefreshOutcome.Issued(issueTokens())
                    }
                    else -> throw refreshFailure
                }
                else -> null
            }
        })
}
