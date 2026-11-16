package dev.usbharu.toloidp.devicegrant

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.config.IdpProperties
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
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

    @Test
    fun missingAuthorizationHeaderIsRejected() {
        assertFailsWith<BffAuthenticationException> { authenticator(null).authenticate(null) }
    }

    @Test
    fun nonBasicAuthorizationSchemeIsRejected() {
        assertFailsWith<BffAuthenticationException> {
            authenticator(null).authenticate("Bearer console-ui:secret")
        }
    }

    @Test
    fun malformedBase64CredentialsAreRejected() {
        assertFailsWith<BffAuthenticationException> {
            authenticator(null).authenticate("Basic not-base64!")
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["", ":", "console-ui:", ":secret"])
    fun credentialsWithoutANonEmptyClientIdAndSecretAreRejected(credentials: String) {
        val malformed = "Basic " + Base64.getEncoder().encodeToString(credentials.toByteArray())

        assertFailsWith<BffAuthenticationException> { authenticator(null).authenticate(malformed) }
    }

    @Test
    fun wrongClientSecretIsRejected() {
        val wrongSecret = "Basic " + Base64.getEncoder().encodeToString("console-ui:wrong".toByteArray())

        assertFailsWith<BffAuthenticationException> { authenticator(null).authenticate(wrongSecret) }
    }

    @Test
    fun unknownClientIsRejected() {
        val unknownClient = "Basic " + Base64.getEncoder().encodeToString("unknown-client:secret".toByteArray())

        assertFailsWith<BffAuthenticationException> { authenticator(null).authenticate(unknownClient) }
    }

    @Test
    fun clientOtherThanTheConfiguredBffClientIsRejected() {
        val otherClient = "Basic " + Base64.getEncoder().encodeToString("other-client:secret".toByteArray())
        val authenticator = authenticator(null, clientId = "other-client", bffClientId = "console-ui")

        assertFailsWith<BffAuthenticationException> { authenticator.authenticate(otherClient) }
    }

    private fun authenticator(
        expiresAt: Instant?,
        clientId: String = "console-ui",
        bffClientId: String = "console-ui",
    ): BffClientAuthenticator {
        val clientBuilder = RegisteredClient.withId("bff-test").clientId(clientId).clientSecret("{noop}secret")
        if (expiresAt != null) clientBuilder.clientSecretExpiresAt(expiresAt)
        val client = clientBuilder
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("events.read").build()
        val configured = ClientPolicy(
            clientId, ClientType.CONFIDENTIAL, setOf("client_credentials"), emptySet(),
            setOf("backend-api"), setOf("events.read"), Duration.ofMinutes(15), Duration.ofMinutes(10),
        ).toRegisteredClient(client)
        return BffClientAuthenticator(
            InMemoryRegisteredClientRepository(configured), PasswordEncoderFactories.createDelegatingPasswordEncoder(),
            IdpProperties(deviceAuthorization = IdpProperties.DeviceAuthorization(bffClientId = bffClientId)),
            Clock.fixed(now, ZoneOffset.UTC),
        )
    }
}
