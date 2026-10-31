package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.system.CapturedOutput
import org.springframework.boot.test.system.OutputCaptureExtension
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:login-challenge-flow;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension::class)
class LoginChallengeFlowTests(
    @Autowired private val mvc: MockMvc,
    @Autowired private val cache: RelationMembershipCacheRepository,
    @Autowired private val json: JsonMapper,
    @Autowired private val decoder: JwtDecoder,
) {
    @BeforeEach
    fun membership() {
        cache.deleteAll()
        cache.save(RelationMembershipCache(
            cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
            membership = TenantMembership("tenant-a", RelationRole.OWNER, emptyList()),
            cachedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(300),
        ))
    }

    @Test
    fun authorizationWithoutLoginStateRedirectsToTheLoginPageWithAFreshChallenge() {
        val first = mvc.challengeFrom(authorize())
        val second = mvc.challengeFrom(authorize())
        assertNotEquals(first, second)
        assertTrue(first.matches(Regex("[A-Za-z0-9_-]{43,}")))
    }

    @Test
    fun invalidRequestsReturnToTheClientBeforeAChallengeIsIssued() {
        assertClientError(mvc.perform(authorize(resource = null)), "invalid_request")
        assertClientError(mvc.perform(authorize(resource = "https://api.example.com/tenants/tenant-a/events/event-1")), "invalid_target")
        assertClientError(mvc.perform(authorize(scope = "openid unregistered.scope")), "invalid_scope")
    }

    @Test
    fun authenticatedChallengeResumesTheOriginalRequestExactlyOnce(output: CapturedOutput) {
        val challenge = mvc.challengeFrom(authorize().queryParam("nonce", " nonce with spaces ").queryParam("prompt", "login"))
        val session = mvc.loginWithChallengeSession(challenge)
        val tokens = exchange(mvc.perform(resumeAuthorization(challenge, session)))
        val idToken = decoder.decode(tokens["id_token"].stringValue())
        assertEquals(" nonce with spaces ", idToken.getClaimAsString("nonce"))
        assertEquals(authenticationTime(session), idToken.getClaimAsInstant("auth_time"))
        assertEquals("tenant-a", decoder.decode(tokens["access_token"].stringValue()).getClaimAsString("tenant_id"))
        assertLoginErrorPage(mvc.perform(resumeAuthorization(challenge, session)))
        assertFalse(output.all.contains(challenge))
    }

    @ParameterizedTest
    @ValueSource(strings = ["prompt", "max_age"])
    fun forcedLoginIssuesANewChallengeEvenWithLoginState(parameter: String) {
        val session = signedIn()
        val challenge = mvc.challengeFrom(authorize(session).queryParam(parameter, if (parameter == "prompt") "login" else "0"))
        assertLoginErrorPage(mvc.perform(resumeAuthorization(challenge, session)))
        val before = authenticationTime(session)
        mvc.loginWithChallengeSession(challenge, session = session)
        val idToken = decoder.decode(exchange(mvc.perform(resumeAuthorization(challenge, session)))["id_token"].stringValue())
        assertEquals(authenticationTime(session), idToken.getClaimAsInstant("auth_time"))
        assertFalse(idToken.getClaimAsInstant("auth_time").isBefore(before))
    }

    @Test
    fun anotherChallengesLoginDoesNotSatisfyAForcedLogin() {
        val session = signedIn()
        val forced = mvc.challengeFrom(authorize(session).queryParam("prompt", "login"))
        val other = mvc.challengeFrom(authorize(session).queryParam("prompt", "login"))
        assertNotEquals(forced, other)
        mvc.loginWithChallengeSession(other, session = session)
        assertLoginErrorPage(mvc.perform(resumeAuthorization(forced, session)))
        exchange(mvc.perform(resumeAuthorization(other, session)))
    }

    @Test
    fun challengeAuthenticatedInAnotherSessionIsRejected() {
        val challenge = mvc.challengeFrom(authorize())
        val owner = mvc.loginWithChallengeSession(challenge)
        assertLoginErrorPage(mvc.perform(resumeAuthorization(challenge, signedIn())))
        assertLoginErrorPage(mvc.perform(resumeAuthorization(challenge)))
        exchange(mvc.perform(resumeAuthorization(challenge, owner)))
    }

    @Test
    fun loginRejectsChallengesItCannotAuthenticateWithoutUnauthorized() {
        mvc.perform(loginWithChallenge("unknown-challenge")).andExpect(status().isBadRequest)
        mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON)
            .content("""{"username":"user-123","password":"password"}""")).andExpect(status().isBadRequest)
        val challenge = mvc.challengeFrom(authorize())
        mvc.perform(loginWithChallenge(challenge, password = "wrong-password")).andExpect(status().isUnauthorized)
        mvc.loginWithChallengeSession(challenge)
        mvc.perform(loginWithChallenge(challenge)).andExpect(status().isBadRequest)
    }

    @Test
    fun resumeAcceptsOnlyTheChallengeParameter() {
        val challenge = mvc.challengeFrom(authorize())
        val session = mvc.loginWithChallengeSession(challenge)
        assertLoginErrorPage(mvc.perform(resumeAuthorization(challenge, session).queryParam("client_id", "client-123")))
        assertLoginErrorPage(mvc.perform(resumeAuthorization(challenge, session).queryParam("challenge", challenge)))
        assertLoginErrorPage(mvc.perform(post("/oauth2/authorize").param("challenge", challenge).session(session)))
        exchange(mvc.perform(resumeAuthorization(challenge, session)))
    }

    @Test
    fun oversizedAuthorizationRequestGoesToTheErrorPageWithoutAChallenge() {
        val location = mvc.perform(authorize().queryParam("padding", "x".repeat(9000)))
            .andExpect(status().isFound).andReturn().response.redirectedUrl
        assertEquals("$LOGIN_ERROR_PAGE?error=invalid_request", location)
    }

    private fun signedIn(): MockHttpSession = mvc.loginWithChallengeSession(mvc.challengeFrom(authorize()))

    private fun authenticationTime(session: MockHttpSession): Instant {
        val context = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) as SecurityContext
        return Instant.ofEpochSecond(OidcAuthenticationRequestValidator.authenticationTime(context.authentication!!)!!)
    }

    private fun authorize(
        session: MockHttpSession? = null,
        scope: String = "openid tenant.read",
        resource: String? = "https://api.example.com/tenants/tenant-a",
    ): MockHttpServletRequestBuilder {
        val request = get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", "client-123")
            .queryParam("redirect_uri", REDIRECT).queryParam("scope", scope).queryParam("state", "request-state")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method", "S256")
        if (resource != null) request.queryParam("resource", resource)
        if (session != null) request.session(session)
        return request
    }

    private fun assertClientError(result: ResultActions, error: String) {
        val location = result.andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertTrue(location.startsWith("$REDIRECT?"))
        val parameters = UriComponentsBuilder.fromUriString(location).build().queryParams
        assertEquals(error, parameters.getFirst("error"))
        assertNull(parameters.getFirst("code"))
        assertEquals("request-state", parameters.getFirst("state"))
    }

    private fun exchange(result: ResultActions): JsonNode {
        val location = result.andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertTrue(location.startsWith("$REDIRECT?"))
        val parameters = UriComponentsBuilder.fromUriString(location).build().queryParams
        assertEquals("request-state", parameters.getFirst("state"))
        val response = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
            .param("grant_type", "authorization_code").param("code", parameters.getFirst("code")!!).param("redirect_uri", REDIRECT)
            .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
            .andExpect(status().isOk).andReturn().response.contentAsString
        return json.readTree(response)
    }

    companion object {
        private const val REDIRECT = "http://127.0.0.1:8080/login/oauth2/code/client-123"
    }
}
