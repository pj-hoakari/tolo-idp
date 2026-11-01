package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:registration-flow;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
@AutoConfigureMockMvc
class RegistrationFlowTests(
    @Autowired private val mvc: MockMvc,
    @Autowired private val json: JsonMapper,
    @Autowired private val decoder: JwtDecoder,
    @Autowired private val users: IdpUserDetailsManager,
) {
    @Test
    fun loginWithARegistrationChallengeDoesNotRequireTenantMembership() {
        val tenantAccess = mvc.challengeFrom(authorize(scope = "openid tenant.read", resource = "https://api.example.com/tenants/tenant-a"))
        mvc.perform(loginWithChallenge(tenantAccess)).andExpect(status().isForbidden)

        val challenge = mvc.challengeFrom(authorize(resource = "https://api.example.com/tenants/tenant-a"))
        val session = mvc.loginWithChallengeSession(challenge)
        val access = decoder.decode(exchange(mvc.perform(resumeAuthorization(challenge, session)))["access_token"].stringValue())
        assertEquals(TOKEN_USE_REGISTRATION, access.getClaimAsString("token_use"))
        assertEquals(IdpUserDetailsManager.DEVELOPMENT_USER_ID, access.subject)
    }

    @ParameterizedTest
    @ValueSource(strings = ["openid tenant.join", "tenant.join tenant.read", "profile tenant.join"])
    fun tenantJoinMixedWithOtherScopesIsRejectedBeforeAChallenge(scope: String) {
        val location = mvc.perform(authorize(scope = scope)).andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertTrue(location.startsWith("$REDIRECT?"))
        assertEquals("invalid_scope", UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("error"))
    }

    @Test
    fun tenantClaimIsRejectedAsUnsupported() {
        val location = mvc.perform(authorize(scope = "tenant.claim")).andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertEquals("invalid_scope", UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("error"))
    }

    private fun authorize(scope: String = "tenant.join", resource: String = NEW_TENANT_RESOURCE): MockHttpServletRequestBuilder =
        get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", "client-123")
            .queryParam("redirect_uri", REDIRECT).queryParam("scope", scope).queryParam("state", "request-state")
            .queryParam("resource", resource)
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method", "S256")

    private fun exchange(result: ResultActions): JsonNode {
        val location = result.andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertTrue(location.startsWith("$REDIRECT?"))
        val code = UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code")!!
        val response = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
            .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", REDIRECT)
            .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
            .andExpect(status().isOk).andReturn().response.contentAsString
        return json.readTree(response)
    }

    companion object {
        private const val REDIRECT = "http://127.0.0.1:8080/login/oauth2/code/client-123"
        private const val NEW_TENANT = "tenant-new"
        private const val NEW_TENANT_RESOURCE = "https://api.example.com/tenants/tenant-new"
    }
}
