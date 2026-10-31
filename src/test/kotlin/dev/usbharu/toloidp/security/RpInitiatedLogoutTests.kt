package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.core.userdetails.User
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.json.JsonMapper
import java.net.URI
import java.time.Instant
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@SpringBootTest
@AutoConfigureMockMvc
class RpInitiatedLogoutTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val jsonMapper: JsonMapper,
    @Autowired private val users: IdpUserDetailsManager,
) {
    @BeforeEach
    fun setUp() {
        cacheRepository.deleteAll()
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
                membership = TenantMembership("tenant-a", RelationRole.OWNER, listOf(EventMembership("event-1", RelationRole.OWNER))),
                cachedAt = Instant.EPOCH,
                expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        )
    }

    @Test
    fun discoveryPublishesEndSessionEndpoint() {
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.end_session_endpoint").value("http://localhost:8080/connect/logout"))
    }

    @ParameterizedTest
    @ValueSource(strings = ["GET", "POST"])
    fun endSessionWithoutClientIdEndsIdpSessionAndRedirectsToRegisteredUriWithState(method: String) {
        val session = login()
        val idToken = issueTokens(session).getValue("id_token")

        mockMvc.perform(endSession(HttpMethod.valueOf(method), session, idToken))
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("$POST_LOGOUT_REDIRECT_URI?state=tenant-a.example.com%3A3000"))
            .andExpect(content().string(""))

        assertTrue(session.isInvalid)
    }

    @Test
    fun endSessionWithoutIdpSessionStillRedirects() {
        val idToken = issueTokens(login()).getValue("id_token")

        mockMvc.perform(endSession(HttpMethod.GET, null, idToken))
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("$POST_LOGOUT_REDIRECT_URI?state=tenant-a.example.com%3A3000"))
    }

    @Test
    fun unregisteredPostLogoutRedirectUriIsRejectedWithoutRedirectOrEndingSession() {
        val session = login()
        val idToken = issueTokens(session).getValue("id_token")

        mockMvc.perform(endSession(HttpMethod.GET, session, idToken, "https://attacker.example/auth/logged-out"))
            .andExpect(status().isBadRequest)
            .andExpect(header().doesNotExist("Location"))
            .andExpect(jsonPath("$.error").value("invalid_request"))
            .andExpect(jsonPath("$.error_description").doesNotExist())

        assertFalse(session.isInvalid)
        issueTokens(session)
    }

    @Test
    fun missingIdTokenHintIsRejectedWithoutEndingSession() {
        val session = login()

        mockMvc.perform(
            get("/connect/logout")
                .session(session)
                .queryParam("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                .queryParam("state", "state"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(header().doesNotExist("Location"))
            .andExpect(jsonPath("$.error").value("invalid_request"))

        assertFalse(session.isInvalid)
    }

    @Test
    fun onlyTheLatestIdTokenOfAnAuthorizationIsAcceptedAsHint() {
        val session = login()
        val tokens = issueTokens(session)
        val refreshed = mockMvc.perform(
            post("/oauth2/token")
                .with(httpBasic("client-123", "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "refresh_token")
                .param("refresh_token", tokens.getValue("refresh_token")),
        )
            .andExpect(status().isOk)
            .andReturn()
            .response
        val refreshedIdToken = jsonMapper.readTree(refreshed.contentAsString)["id_token"].stringValue()

        mockMvc.perform(endSession(HttpMethod.GET, session, tokens.getValue("id_token")))
            .andExpect(status().isBadRequest)
            .andExpect(header().doesNotExist("Location"))
            .andExpect(jsonPath("$.error").value("invalid_token"))
        assertFalse(session.isInvalid)

        mockMvc.perform(endSession(HttpMethod.GET, session, refreshedIdToken))
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("$POST_LOGOUT_REDIRECT_URI?state=tenant-a.example.com%3A3000"))
        assertTrue(session.isInvalid)
    }

    @Test
    fun idTokenIssuedBeforeReloginInTheSameBrowserRedirectsWithoutEndingCurrentSession() {
        val session = login()
        val earlier = issueTokens(session).getValue("id_token")
        login(session)
        issueTokens(session)

        mockMvc.perform(endSession(HttpMethod.GET, session, earlier))
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("$POST_LOGOUT_REDIRECT_URI?state=tenant-a.example.com%3A3000"))
        assertFalse(session.isInvalid)
        issueTokens(session)
    }

    @Test
    fun idTokenOfAnotherUserRedirectsWithoutEndingCurrentSession() {
        users.createUser("tenant-b", User.withUsername("user-b").password("{noop}password-b").roles("USER").build())
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId("tenant-b", "user-b"),
                membership = TenantMembership("tenant-b", RelationRole.OWNER, listOf(EventMembership("event-1", RelationRole.OWNER))),
                cachedAt = Instant.EPOCH,
                expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        )
        try {
            val session = login()
            val userAIdToken = issueTokens(session).getValue("id_token")
            login(session, "tenant-b", "user-b", "password-b")
            issueTokens(session)

            mockMvc.perform(endSession(HttpMethod.GET, session, userAIdToken))
                .andExpect(status().isFound)
                .andExpect(redirectedUrl("$POST_LOGOUT_REDIRECT_URI?state=tenant-a.example.com%3A3000"))
            assertFalse(session.isInvalid)
            issueTokens(session)
        } finally {
            users.deleteUser("tenant-b", "user-b")
        }
    }

    @Test
    fun apiLogoutNoLongerEndsSession() {
        val session = login()

        mockMvc.perform(post("/api/logout").session(session))
            .andExpect(status().isNotFound)

        assertFalse(session.isInvalid)
    }

    private fun endSession(method: HttpMethod, session: MockHttpSession?, idToken: String, postLogoutRedirectUri: String = POST_LOGOUT_REDIRECT_URI): MockHttpServletRequestBuilder {
        val parameters = mapOf(
            "id_token_hint" to idToken,
            "post_logout_redirect_uri" to postLogoutRedirectUri,
            "state" to "tenant-a.example.com:3000",
        )
        val builder = request(method, "/connect/logout")
        if (session != null) builder.session(session)
        if (method == HttpMethod.GET) {
            parameters.forEach { (name, value) -> builder.queryParam(name, value) }
        } else {
            builder.contentType(MediaType.APPLICATION_FORM_URLENCODED)
            parameters.forEach { (name, value) -> builder.param(name, value) }
        }
        return builder
    }

    private fun login(
        session: MockHttpSession = MockHttpSession(),
        tenantId: String = "tenant-a",
        username: String = "user-123",
        password: String = "password",
    ): MockHttpSession =
        mockMvc.perform(
            post("/api/login")
                .session(session)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"username":"$username","password":"$password","tenantId":"$tenantId"}"""),
        )
            .andExpect(status().isOk)
            .andReturn()
            .request
            .session as MockHttpSession

    private fun issueTokens(session: MockHttpSession): Map<String, String> {
        val authorization = mockMvc.perform(
            get("/oauth2/authorize")
                .session(session)
                .queryParam("response_type", "code")
                .queryParam("client_id", "client-123")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid tenant.read")
                .queryParam("state", "state")
                .queryParam("audience", "backend-api")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256"),
        )
            .andExpect(status().isFound)
            .andReturn()
            .response
        val code = UriComponentsBuilder.fromUri(URI.create(authorization.redirectedUrl!!)).build().queryParams.getFirst("code")!!
        val response = mockMvc.perform(
            post("/oauth2/token")
                .with(httpBasic("client-123", "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", REDIRECT_URI)
                .param("code_verifier", CODE_VERIFIER),
        )
            .andExpect(status().isOk)
            .andReturn()
            .response
        val body = jsonMapper.readTree(response.contentAsString)
        return listOf("id_token", "refresh_token").associateWith { body[it].stringValue() }
    }

    private companion object {
        const val REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/client-123"
        const val POST_LOGOUT_REDIRECT_URI = "http://localhost:3000/auth/logged-out"
        const val CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        const val CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    }
}
