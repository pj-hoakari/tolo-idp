package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.ArgumentMatchers.anyMap
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import java.net.URI
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Tag("unit")
class AuthorizationErrorResponseHandlerTests {
    private val challenges = mock(LoginChallenges::class.java)
    private val handler = AuthorizationErrorResponseHandler(
        challenges,
        mock(RegisteredClientRepository::class.java),
        URI("https://login.example.com/login"),
        URI("https://login.example.com/error"),
    )
    private val captured = AtomicReference<Map<String, Array<String>>>()

    @Test
    fun storesNonStandardParametersForLoginChallenge() {
        stubIssue("challenge-1")
        val token = token(
            redirectUri = "https://client.example.com/callback",
            scopes = setOf("openid", "tenant.read"),
            state = "state-1",
            additionalParameters = linkedMapOf(
                OAuth2ParameterNames.RESPONSE_TYPE to "code",
                "resource" to "https://api.example.com/tenants/tenant-a",
                "audience" to arrayOf("backend-api"),
                "ui_locales" to listOf("ja", "en", 42),
                "unsupported" to 42,
            ),
        )

        val response = handle(token)

        val parameters = captured.get()
        assertContentEquals(arrayOf("code"), parameters[OAuth2ParameterNames.RESPONSE_TYPE])
        assertContentEquals(arrayOf("client-123"), parameters[OAuth2ParameterNames.CLIENT_ID])
        assertContentEquals(arrayOf("https://client.example.com/callback"), parameters[OAuth2ParameterNames.REDIRECT_URI])
        assertContentEquals(arrayOf("openid tenant.read"), parameters[OAuth2ParameterNames.SCOPE])
        assertContentEquals(arrayOf("state-1"), parameters[OAuth2ParameterNames.STATE])
        assertContentEquals(arrayOf("https://api.example.com/tenants/tenant-a"), parameters["resource"])
        assertContentEquals(arrayOf("backend-api"), parameters["audience"])
        assertContentEquals(arrayOf("ja", "en"), parameters["ui_locales"])
        assertFalse(parameters.containsKey("unsupported"))
        assertTrue(response.redirectedUrl!!.startsWith("https://login.example.com/login?challenge=challenge-1"))
    }

    @Test
    fun omitsBlankOptionalParameters() {
        stubIssue("challenge-2")
        val token = token(redirectUri = " ", scopes = emptySet(), state = " ", additionalParameters = emptyMap())

        val response = handle(token)

        val parameters = captured.get()
        assertFalse(parameters.containsKey(OAuth2ParameterNames.REDIRECT_URI))
        assertFalse(parameters.containsKey(OAuth2ParameterNames.SCOPE))
        assertFalse(parameters.containsKey(OAuth2ParameterNames.STATE))
        assertTrue(response.redirectedUrl!!.startsWith("https://login.example.com/login?challenge=challenge-2"))
    }

    @Test
    fun fallsBackToErrorPageWhenChallengeCannotBeIssued() {
        stubIssue(null)
        val response = handle(token())

        assertEquals("https://login.example.com/error?error=invalid_request", response.redirectedUrl)
    }

    private fun stubIssue(challenge: String?) {
        captured.set(null)
        `when`(challenges.issue(anyString(), anyString(), anyMap(), anyBoolean())).thenAnswer { invocation ->
            @Suppress("UNCHECKED_CAST")
            captured.set(invocation.getArgument(2) as Map<String, Array<String>>)
            challenge
        }
    }

    private fun handle(token: OAuth2AuthorizationCodeRequestAuthenticationToken): MockHttpServletResponse {
        val response = MockHttpServletResponse()
        handler.onAuthenticationFailure(
            MockHttpServletRequest(),
            response,
            LoginChallengeRequiredException(token, "tenant-a"),
        )
        return response
    }

    private fun token(
        redirectUri: String? = "https://client.example.com/callback",
        scopes: Set<String> = setOf("openid"),
        state: String? = "state-1",
        additionalParameters: Map<String, Any> = emptyMap(),
    ): OAuth2AuthorizationCodeRequestAuthenticationToken =
        OAuth2AuthorizationCodeRequestAuthenticationToken(
            "https://issuer.example.com/oauth2/authorize",
            "client-123",
            UsernamePasswordAuthenticationToken.authenticated("client-123", null, emptyList()),
            redirectUri,
            state,
            scopes,
            additionalParameters,
        )
}
