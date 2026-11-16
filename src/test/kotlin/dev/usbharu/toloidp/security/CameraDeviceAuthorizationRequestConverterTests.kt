package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@Tag("unit")
class CameraDeviceAuthorizationRequestConverterTests {
    private val client = RegisteredClient.withId("client-id")
        .clientId("public-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
        .scope("device.read")
        .build()
    private val converter = CameraDeviceAuthorizationRequestConverter()

    @BeforeEach
    fun setUpSecurityContext() {
        SecurityContextHolder.getContext().authentication =
            OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null)
    }

    @AfterEach
    fun clearSecurityContext() {
        SecurityContextHolder.clearContext()
    }

    @Test
    fun rejectsAnEventIdSuppliedByTheCamera() {
        val request = deviceAuthorizationRequest().apply { addParameter("event_id", "event-1") }

        val error = assertFailsWith<OAuth2AuthenticationException> { converter.convert(request) }

        assertEquals("invalid_request", error.error.errorCode)
    }

    @Test
    fun rejectsAnEdgeDeviceIdSuppliedByTheCamera() {
        val request = deviceAuthorizationRequest().apply { addParameter("edge_device_id", "edge-1") }

        val error = assertFailsWith<OAuth2AuthenticationException> { converter.convert(request) }

        assertEquals("invalid_request", error.error.errorCode)
    }

    @Test
    fun passesARequestWithoutCameraBindingsToTheDelegate() {
        val converted = converter.convert(deviceAuthorizationRequest()) as OAuth2DeviceAuthorizationRequestAuthenticationToken

        assertEquals(setOf("device.read"), converted.scopes)
    }

    private fun deviceAuthorizationRequest(): MockHttpServletRequest =
        MockHttpServletRequest("POST", "/oauth2/device_authorization").apply {
            addParameter("client_id", "public-client")
            addParameter("scope", "device.read")
        }
}
