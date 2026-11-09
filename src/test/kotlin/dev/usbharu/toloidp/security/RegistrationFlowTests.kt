package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.scope.IdpScopes
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.Duration
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:registration-flow;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
@AutoConfigureMockMvc
class RegistrationFlowTests(
    @Autowired private val mvc: MockMvc,
    @Autowired private val json: JsonMapper,
    @Autowired private val decoder: JwtDecoder,
    @Autowired private val users: IdpUserDetailsManager,
    @Autowired private val clients: RegisteredClientRepository,
    @Autowired private val passwordEncoder: PasswordEncoder,
) {
    @Test
    fun signupCreatesTheUserInTheChallengeTenantAndIssuesARegistrationToken() {
        val username = uniqueUsername()
        val challenge = mvc.challengeFrom(authorize())
        val preSignup = MockHttpSession()
        val originalSessionId = preSignup.id
        val signup = mvc.perform(signupRequest(challenge, username, extra = ""","tenantId":"tenant-a"""").session(preSignup))
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.username").value(username))
            .andExpect(jsonPath("$.tenantId").value(NEW_TENANT))
            .andExpect(jsonPath("$.resource").value(NEW_TENANT_RESOURCE))
            .andReturn()
        val session = signup.request.session as MockHttpSession
        assertNotEquals(originalSessionId, session.id)
        val subject = json.readTree(signup.response.contentAsString)["sub"].stringValue()
        assertEquals(subject, users.loadUserByUsername(NEW_TENANT, username).id)
        val created = users.loadUserById(subject)
        assertTrue(created.isEnabled)
        assertEquals(listOf("ROLE_USER"), created.authorities.map { it.authority })
        assertTrue(passwordEncoder.matches("correct horse", created.password))
        assertFalse(users.userExists("tenant-a", username))

        val tokens = exchange(mvc.perform(resumeAuthorization(challenge, session)))
        assertNull(tokens["id_token"])
        assertEquals("tenant.join", tokens["scope"].stringValue())
        val access = decoder.decode(tokens["access_token"].stringValue())
        assertEquals(TOKEN_USE_REGISTRATION, access.getClaimAsString("token_use"))
        assertEquals("tenant.join", access.getClaimAsString("scope"))
        assertEquals(subject, access.subject)
        assertEquals(listOf("backend-api"), access.audience)
        assertEquals("client-123", access.getClaimAsString("client_id"))
        assertTrue(Duration.between(access.issuedAt, access.expiresAt) <= Duration.ofMinutes(5))
        assertFalse(access.hasClaim("tenant_id"))
        assertFalse(access.hasClaim("event_id"))
        assertFalse(access.hasClaim("resource"))

        mvc.perform(post("/oauth2/introspect").with(httpBasic("service-gateway", "gateway-secret")).param("token", access.tokenValue))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.token_use").value(TOKEN_USE_REGISTRATION))
            .andExpect(jsonPath("$.tenant_id").doesNotExist())

        mvc.perform(
            post("/oauth2/token").with(httpBasic("client-123", "secret"))
                .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .param("subject_token", access.tokenValue).param("subject_token_type", ACCESS_TOKEN_TYPE)
                .param("audience", "backend-api").param("resource", "$NEW_TENANT_RESOURCE/events/event-1").param("scope", "events.read"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        assertNull(tokens["refresh_token"])
    }

    @Test
    fun registrationCodeIsRejectedWhenTenantJoinIsRemovedBeforeRedemption() {
        val challenge = mvc.challengeFrom(authorize())
        val signup = mvc.perform(signupRequest(challenge, uniqueUsername()))
            .andExpect(status().isCreated)
            .andReturn()
        val session = signup.request.session as MockHttpSession
        val code = codeFrom(mvc.perform(resumeAuthorization(challenge, session)))
        val original = checkNotNull(clients.findByClientId("client-123"))
        try {
            clients.save(
                RegisteredClient.from(original)
                    .scopes { scopes -> scopes.remove(IdpScopes.TENANT_JOIN) }
                    .build(),
            )
            mvc.perform(
                post("/oauth2/token").with(httpBasic("client-123", "secret"))
                    .param("grant_type", "authorization_code")
                    .param("code", code)
                    .param("redirect_uri", REDIRECT)
                    .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            )
                .andExpect(status().isBadRequest)
                .andExpect(jsonPath("$.error").value("invalid_scope"))
        } finally {
            clients.save(original)
        }
    }

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

    @Test
    fun loginStateFromAnotherTenantRequiresANewChallengeForARegistration() {
        val first = mvc.challengeFrom(authorize())
        val session = mvc.perform(signupRequest(first, uniqueUsername())).andExpect(status().isCreated)
            .andReturn().request.session as MockHttpSession
        exchange(mvc.perform(resumeAuthorization(first, session)))

        val sameTenant = mvc.perform(authorize().session(session)).andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertTrue(sameTenant.startsWith("$REDIRECT?"))

        val otherTenant = mvc.challengeFrom(authorize(resource = "https://api.example.com/tenants/tenant-c").session(session))
        assertNotEquals(first, otherTenant)
    }

    @Test
    fun signupRejectsAUsernameAlreadyRegisteredInTheTenant() {
        val username = uniqueUsername()
        mvc.perform(signupRequest(mvc.challengeFrom(authorize()), username)).andExpect(status().isCreated)
        val challenge = mvc.challengeFrom(authorize())
        mvc.perform(signupRequest(challenge, username)).andExpect(status().isConflict)
        mvc.perform(signupRequest(mvc.challengeFrom(authorize(resource = "https://api.example.com/tenants/tenant-c")), username))
            .andExpect(status().isCreated)
    }

    @Test
    fun signupRequiresAPendingRegistrationChallenge() {
        val tenantAccess = mvc.challengeFrom(authorize(scope = "openid tenant.read"))
        mvc.perform(signupRequest(tenantAccess, uniqueUsername())).andExpect(status().isBadRequest)
        mvc.perform(signupRequest("unknown-challenge", uniqueUsername())).andExpect(status().isBadRequest)

        val challenge = mvc.challengeFrom(authorize())
        mvc.perform(signupRequest(challenge, uniqueUsername())).andExpect(status().isCreated)
        mvc.perform(signupRequest(challenge, uniqueUsername())).andExpect(status().isBadRequest)
    }

    @ParameterizedTest
    @ValueSource(strings = ["", " leading", "has space", "trailing ", "tab\tname"])
    fun signupRejectsInvalidUsernames(username: String) {
        mvc.perform(signupRequest(mvc.challengeFrom(authorize()), username)).andExpect(status().isBadRequest)
    }

    @Test
    fun signupRejectsPasswordsOutsideTheAcceptedLength() {
        mvc.perform(signupRequest(mvc.challengeFrom(authorize()), uniqueUsername(), password = "short")).andExpect(status().isBadRequest)
        mvc.perform(signupRequest(mvc.challengeFrom(authorize()), uniqueUsername(), password = "a".repeat(73))).andExpect(status().isBadRequest)
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

    private fun uniqueUsername() = "owner-${UUID.randomUUID().toString().take(8)}"

    private fun signupRequest(challenge: String, username: String, password: String = "correct horse", extra: String = ""): MockHttpServletRequestBuilder =
        post("/api/signup").contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsString(mapOf("username" to username, "password" to password, "challenge" to challenge)).dropLast(1) + extra + "}")

    private fun authorize(scope: String = "tenant.join", resource: String = NEW_TENANT_RESOURCE): MockHttpServletRequestBuilder =
        get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", "client-123")
            .queryParam("redirect_uri", REDIRECT).queryParam("scope", scope).queryParam("state", "request-state")
            .queryParam("resource", resource)
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method", "S256")

    private fun exchange(result: ResultActions): JsonNode {
        val code = codeFrom(result)
        val response = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
            .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", REDIRECT)
            .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
            .andExpect(status().isOk).andReturn().response.contentAsString
        return json.readTree(response)
    }

    private fun codeFrom(result: ResultActions): String {
        val location = result.andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertTrue(location.startsWith("$REDIRECT?"))
        return UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code")!!
    }

    companion object {
        private const val REDIRECT = "http://127.0.0.1:8080/login/oauth2/code/client-123"
        private const val NEW_TENANT = "tenant-new"
        private const val NEW_TENANT_RESOURCE = "https://api.example.com/tenants/tenant-new"
    }
}
