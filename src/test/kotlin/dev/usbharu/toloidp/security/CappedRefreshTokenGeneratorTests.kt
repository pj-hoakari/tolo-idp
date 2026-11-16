package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.devicegrant.DeviceGrant
import dev.usbharu.toloidp.devicegrant.DeviceGrantRepository
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame

@Tag("unit")
class CappedRefreshTokenGeneratorTests {
    private val now = Instant.parse("2026-11-13T00:00:00Z")
    private val client = RegisteredClient.withId("client-id")
        .clientId("client-123")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
        .scope("device.read")
        .build()
    private val authorization = OAuth2Authorization.withRegisteredClient(client)
        .principalName("user-123")
        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
        .build()
    private val grant = DeviceGrant(
        id = "grant-1",
        tenantId = "tenant-a",
        eventId = "event-1",
        edgeDeviceId = "edge-1",
        approverSubject = "staff-1",
        clientId = client.clientId,
        approvedAt = now,
        absoluteExpiresAt = now.plusSeconds(86_400),
        createdAt = now,
    )
    private val deviceGrants = mock(DeviceGrantRepository::class.java)

    @Test
    fun returnsNullWhenTheDelegateGeneratesNothing() {
        assertNull(generatorFor(null).generate(context(authorization)))
    }

    @Test
    fun returnsTheGeneratedTokenWhenTheContextHasNoAuthorization() {
        val generated = refreshToken(expiresAt = now.plusSeconds(3_600))

        assertSame(generated, generatorFor(generated).generate(context(null)))
    }

    @Test
    fun returnsTheGeneratedTokenWhenNoDeviceGrantMatchesTheAuthorization() {
        val generated = refreshToken(expiresAt = now.plusSeconds(3_600))

        assertSame(generated, generatorFor(generated).generate(context(authorization)))
    }

    @Test
    fun returnsTheGeneratedTokenWhenItHasNoExpiry() {
        val generated = refreshToken(expiresAt = null)
        `when`(deviceGrants.findById(authorization.id)).thenReturn(grant)

        assertSame(generated, generatorFor(generated).generate(context(authorization)))
    }

    @Test
    fun capsExpiryAtTheDeviceGrantAbsoluteExpiry() {
        val generated = refreshToken(expiresAt = grant.absoluteExpiresAt.plusSeconds(60))
        `when`(deviceGrants.findById(authorization.id)).thenReturn(grant)

        val capped = generatorFor(generated).generate(context(authorization))

        assertEquals(grant.absoluteExpiresAt, capped?.expiresAt)
    }

    @Test
    fun keepsExpiryBeforeTheDeviceGrantAbsoluteExpiry() {
        val generated = refreshToken(expiresAt = grant.absoluteExpiresAt.minusSeconds(1))
        `when`(deviceGrants.findById(authorization.id)).thenReturn(grant)

        assertSame(generated, generatorFor(generated).generate(context(authorization)))
    }

    @Test
    fun keepsExpiryEqualToTheDeviceGrantAbsoluteExpiry() {
        val generated = refreshToken(expiresAt = grant.absoluteExpiresAt)
        `when`(deviceGrants.findById(authorization.id)).thenReturn(grant)

        assertSame(generated, generatorFor(generated).generate(context(authorization)))
    }

    @Test
    fun cappingPreservesTheTokenValueAndIssuedAt() {
        val generated = refreshToken(expiresAt = grant.absoluteExpiresAt.plusSeconds(60))
        `when`(deviceGrants.findById(authorization.id)).thenReturn(grant)

        val capped = generatorFor(generated).generate(context(authorization))

        assertEquals(generated.tokenValue, capped?.tokenValue)
        assertEquals(generated.issuedAt, capped?.issuedAt)
    }

    private fun refreshToken(expiresAt: Instant?) = OAuth2RefreshToken("refresh-token", now, expiresAt)

    private fun generatorFor(token: OAuth2Token?): CappedRefreshTokenGenerator =
        CappedRefreshTokenGenerator(OAuth2TokenGenerator<OAuth2Token> { token }, deviceGrants)

    private fun context(authorization: OAuth2Authorization?): OAuth2TokenContext =
        object : OAuth2TokenContext {
            override fun getAuthorization(): OAuth2Authorization? = authorization

            override fun <V : Any?> get(key: Any): V? = null

            override fun hasKey(key: Any): Boolean = false
        }
}
