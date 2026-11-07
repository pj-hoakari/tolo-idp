package dev.usbharu.toloidp.devicegrant

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.config.IdpProperties
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BffClientAuthenticatorTests {
    private val now = Instant.parse("2026-11-04T00:00:00Z")
    private val header = "Basic " + Base64.getEncoder().encodeToString("console-ui:secret".toByteArray())

    @Test
    fun expiredSecretIsRejected() {
        assertFailsWith<BffAuthenticationException> { authenticator(now.minusSeconds(1)).authenticate(header) }
    }

    @Test
    fun secretExpiringAtCurrentTimeIsRejected() {
        assertFailsWith<BffAuthenticationException> { authenticator(now).authenticate(header) }
    }

    @Test
    fun futureExpiryIsAccepted() {
        assertEquals("console-ui", authenticator(now.plusSeconds(1)).authenticate(header).clientId)
    }

    @Test
    fun unsetExpiryIsAccepted() {
        assertEquals("console-ui", authenticator(null).authenticate(header).clientId)
    }

    private fun authenticator(expiresAt: Instant?): BffClientAuthenticator {
        val client = RegisteredClient.withId("bff-test").clientId("console-ui").clientSecret("{noop}secret")
            .clientSecretExpiresAt(expiresAt)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("events.read").build()
        val configured = ClientPolicy(
            "console-ui", ClientType.CONFIDENTIAL, setOf("client_credentials"), emptySet(),
            setOf("backend-api"), setOf("events.read"), Duration.ofMinutes(15), Duration.ofMinutes(10),
        ).toRegisteredClient(client)
        return BffClientAuthenticator(
            InMemoryRegisteredClientRepository(configured), PasswordEncoderFactories.createDelegatingPasswordEncoder(),
            IdpProperties(), Clock.fixed(now, ZoneOffset.UTC),
        )
    }
}
