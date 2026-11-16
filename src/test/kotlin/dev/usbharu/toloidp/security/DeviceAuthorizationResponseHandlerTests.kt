package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2DeviceCode
import org.springframework.security.oauth2.core.OAuth2UserCode
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeviceAuthorizationResponseHandlerTests {
    private val now = Instant.parse("2026-11-13T00:00:00Z")
    private val client = RegisteredClient.withId("client-id")
        .clientId("client-123")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
        .scope("device.read")
        .build()
    private val authentication = OAuth2DeviceAuthorizationRequestAuthenticationToken(
        OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null),
        setOf("device.read"),
        OAuth2DeviceCode("device-code", now, now.plusSeconds(300)),
        OAuth2UserCode("USER-CODE", now, now.plusSeconds(300)),
    )
    private val handler = DeviceAuthorizationResponseHandler("https://idp.example.com/device")
    private val json = JsonMapper.builder().build()

    @Test
    fun writesTheDeviceAndUserCodes() {
        val response = responseJson()

        assertEquals("device-code", response["device_code"].asText())
        assertEquals("USER-CODE", response["user_code"].asText())
    }

    @Test
    fun buildsTheVerificationUriCompleteFromTheUserCode() {
        val response = responseJson()

        assertEquals("https://idp.example.com/device", response["verification_uri"].asText())
        assertEquals(
            "https://idp.example.com/device?user_code=USER-CODE",
            response["verification_uri_complete"].asText(),
        )
    }

    @Test
    fun writesTheFiveSecondPollingInterval() {
        assertEquals(5, responseJson()["interval"].asInt())
    }

    @Test
    fun writesTheDeviceCodeLifetime() {
        assertEquals(300, responseJson()["expires_in"].asInt())
    }

    @Test
    fun writesJsonContent() {
        val response = MockHttpServletResponse()

        handler.onAuthenticationSuccess(MockHttpServletRequest(), response, authentication)

        assertTrue(checkNotNull(response.contentType).startsWith("application/json"))
    }

    private fun responseJson(): JsonNode {
        val response = MockHttpServletResponse()
        handler.onAuthenticationSuccess(MockHttpServletRequest(), response, authentication)
        return json.readTree(response.contentAsString)
    }
}
