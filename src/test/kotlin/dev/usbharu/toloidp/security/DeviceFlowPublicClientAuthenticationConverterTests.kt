package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

@Tag("unit")
class DeviceFlowPublicClientAuthenticationConverterTests {
    private val converter = DeviceFlowPublicClientAuthenticationConverter(
        deviceAuthorizationEndpoint = DEVICE_AUTHORIZATION_ENDPOINT,
        tokenEndpoint = TOKEN_ENDPOINT,
    )

    @Test
    fun ignoresNonPostDeviceAuthorizationRequests() {
        val request = MockHttpServletRequest("GET", DEVICE_AUTHORIZATION_ENDPOINT).apply {
            addParameter("client_id", "client-123")
        }

        assertNull(converter.convert(request))
    }

    @Test
    fun ignoresRequestsToOtherEndpoints() {
        val request = MockHttpServletRequest("POST", "/oauth2/authorize").apply {
            addParameter("client_id", "client-123")
        }

        assertNull(converter.convert(request))
    }

    @Test
    fun convertsADeviceAuthorizationRequestWithOneClientId() {
        val authentication = converter.convert(deviceAuthorizationRequest("client-123")) as OAuth2ClientAuthenticationToken

        assertEquals("client-123", authentication.principal)
        assertEquals(ClientAuthenticationMethod.NONE, authentication.clientAuthenticationMethod)
    }

    @Test
    fun convertsADeviceCodeTokenRequest() {
        val authentication = converter.convert(tokenRequest(AuthorizationGrantType.DEVICE_CODE.value, "client-123"))

        assertEquals("client-123", (authentication as OAuth2ClientAuthenticationToken).principal)
    }

    @Test
    fun convertsARefreshTokenRequest() {
        val authentication = converter.convert(tokenRequest(AuthorizationGrantType.REFRESH_TOKEN.value, "client-123"))

        assertEquals("client-123", (authentication as OAuth2ClientAuthenticationToken).principal)
    }

    @Test
    fun ignoresAuthorizationCodeTokenRequests() {
        assertNull(converter.convert(tokenRequest(AuthorizationGrantType.AUTHORIZATION_CODE.value, "client-123")))
    }

    @Test
    fun ignoresRequestsThatCarryAClientSecret() {
        val request = deviceAuthorizationRequest("client-123").apply { addParameter("client_secret", "secret") }

        assertNull(converter.convert(request))
    }

    @Test
    fun rejectsMultipleClientIdParameters() {
        val error = assertFailsWith<OAuth2AuthenticationException> {
            converter.convert(deviceAuthorizationRequest("client-123", "other-client"))
        }

        assertEquals("invalid_request", error.error.errorCode)
    }

    @Test
    fun rejectsBlankClientId() {
        val error = assertFailsWith<OAuth2AuthenticationException> {
            converter.convert(deviceAuthorizationRequest(" "))
        }

        assertEquals("invalid_request", error.error.errorCode)
    }

    @Test
    fun returnsNullWhenClientIdIsMissing() {
        assertNull(converter.convert(MockHttpServletRequest("POST", DEVICE_AUTHORIZATION_ENDPOINT)))
    }

    private fun deviceAuthorizationRequest(vararg clientIds: String): MockHttpServletRequest =
        MockHttpServletRequest("POST", DEVICE_AUTHORIZATION_ENDPOINT).apply {
            addParameter("scope", "device.read")
            clientIds.forEach { addParameter("client_id", it) }
        }

    private fun tokenRequest(grantType: String, vararg clientIds: String): MockHttpServletRequest =
        MockHttpServletRequest("POST", TOKEN_ENDPOINT).apply {
            addParameter("grant_type", grantType)
            clientIds.forEach { addParameter("client_id", it) }
        }

    private companion object {
        const val DEVICE_AUTHORIZATION_ENDPOINT = "/oauth2/device_authorization"
        const val TOKEN_ENDPOINT = "/oauth2/token"
    }
}
