package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Tag("unit")
class DeviceFlowPublicClientAuthenticationProviderTests {
    private val publicClient = RegisteredClient.withId("public-id")
        .clientId("public-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
        .scope("device.read")
        .build()
    private val confidentialClient = RegisteredClient.withId("confidential-id")
        .clientId("confidential-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
        .scope("device.read")
        .build()
    private val provider = DeviceFlowPublicClientAuthenticationProvider(
        InMemoryRegisteredClientRepository(publicClient, confidentialClient),
    )
    private val converter = DeviceFlowPublicClientAuthenticationConverter(
        deviceAuthorizationEndpoint = "/oauth2/device_authorization",
        tokenEndpoint = "/oauth2/token",
    )

    @Test
    fun returnsNullForAuthenticationMethodsOtherThanNone() {
        val authentication = OAuth2ClientAuthenticationToken(
            "public-client",
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
            null,
            emptyMap(),
        )

        assertNull(provider.authenticate(authentication))
    }

    @Test
    fun returnsNullForNoneAuthenticationWithoutTheDeviceFlowMarker() {
        val authentication = OAuth2ClientAuthenticationToken(
            "public-client",
            ClientAuthenticationMethod.NONE,
            null,
            emptyMap(),
        )

        assertNull(provider.authenticate(authentication))
    }

    @Test
    fun authenticatesARegisteredPublicClient() {
        val authentication = provider.authenticate(deviceFlowAuthentication("public-client")) as OAuth2ClientAuthenticationToken

        assertEquals(publicClient, authentication.registeredClient)
        assertEquals(ClientAuthenticationMethod.NONE, authentication.clientAuthenticationMethod)
    }

    @Test
    fun rejectsAnUnknownClient() {
        val error = assertFailsWith<OAuth2AuthenticationException> {
            provider.authenticate(deviceFlowAuthentication("missing-client"))
        }

        assertEquals("invalid_client", error.error.errorCode)
    }

    @Test
    fun rejectsAClientThatDoesNotAllowNoneAuthentication() {
        val error = assertFailsWith<OAuth2AuthenticationException> {
            provider.authenticate(deviceFlowAuthentication("confidential-client"))
        }

        assertEquals("invalid_client", error.error.errorCode)
    }

    @Test
    fun supportsOAuth2ClientAuthenticationTokensOnly() {
        assertTrue(provider.supports(OAuth2ClientAuthenticationToken::class.java))
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken::class.java))
    }

    private fun deviceFlowAuthentication(clientId: String) =
        checkNotNull(converter.convert(
            MockHttpServletRequest("POST", "/oauth2/device_authorization").apply {
                addParameter("client_id", clientId)
            },
        ))
}
