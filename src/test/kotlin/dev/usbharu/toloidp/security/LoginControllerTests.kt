package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.mock.web.MockHttpSession
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.json.JsonMapper
import java.time.Instant
import kotlin.test.assertTrue

@SpringBootTest
@AutoConfigureMockMvc
class LoginControllerTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val jsonMapper: JsonMapper,
) {
    @BeforeEach
    fun setUp() {
        cacheRepository.deleteAll()
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
                membership = TenantMembership(
                    tenantId = "tenant-a",
                    tenantRole = RelationRole.OWNER,
                    events = listOf(EventMembership("event-1", RelationRole.STAFF)),
                ),
                cachedAt = Instant.EPOCH,
                expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        )
    }

    @Test
    fun loginCreatesSessionAndReturnsSelectedTenantResource() {
        mockMvc.perform(loginRequest("user-123", "password", "tenant-a"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.username").value("user-123"))
            .andExpect(jsonPath("$.tenantId").value("tenant-a"))
            .andExpect(jsonPath("$.resource").value("https://api.example.com/tenants/tenant-a"))
            .andExpect(jsonPath("$.authorities[0]").value("ROLE_USER"))
            .andExpect(content().string(not(containsString("password"))))
    }

    @Test
    fun loginInvalidatesExistingSessionBeforeAuthentication() {
        val preAuthSession = MockHttpSession()

        mockMvc.perform(loginRequest("user-123", "password", "tenant-a").session(preAuthSession))
            .andExpect(status().isOk)

        assertTrue(preAuthSession.isInvalid)
    }

    @Test
    fun loginRejectsBadCredentials() {
        mockMvc.perform(loginRequest("user-123", "wrong-password", "tenant-a"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun loginRejectsUnknownUser() {
        mockMvc.perform(loginRequest("missing-user", "password", "tenant-a"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun loginRejectsTenantWithoutMembership() {
        mockMvc.perform(loginRequest("user-123", "password", "tenant-missing"))
            .andExpect(status().isForbidden)
    }

    @Test
    fun loginRejectsInvalidTenantIdWithoutTrimming() {
        mockMvc.perform(loginRequest("user-123", "password", " tenant-a"))
            .andExpect(status().isBadRequest)
    }

    @Test
    fun logoutInvalidatesExistingSession() {
        val session = mockMvc.perform(loginRequest("user-123", "password", "tenant-a"))
            .andExpect(status().isOk)
            .andReturn()
            .request
            .session as MockHttpSession

        mockMvc.perform(post("/api/logout").session(session))
            .andExpect(status().isNoContent)
    }

    @Test
    fun openIdAuthorizationCodeCanBeUsedAtUserInfoEndpoint() {
        val session = mockMvc.perform(loginRequest("user-123", "password", "tenant-a"))
            .andExpect(status().isOk)
            .andReturn()
            .request
            .session as MockHttpSession

        val authorizationResponse = mockMvc.perform(
            get("/oauth2/authorize")
                .session(session)
                .queryParam("response_type", "code")
                .queryParam("client_id", "client-123")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid tenant.read")
                .queryParam("state", "state")
                .queryParam("nonce", "nonce")
                .queryParam("audience", "backend-api")
                .queryParam("code_challenge", CODE_CHALLENGE)
                .queryParam("code_challenge_method", "S256"),
        )
            .andExpect(status().isFound)
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("code=")))
            .andReturn()
            .response

        val code = UriComponentsBuilder.fromUri(authorizationResponse.redirectedUrl!!.let(java.net.URI::create))
            .build()
            .queryParams
            .getFirst("code")!!
        val tokenResponse = mockMvc.perform(
            post("/oauth2/token")
                .with(httpBasic("client-123", "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", REDIRECT_URI)
                .param("code_verifier", CODE_VERIFIER),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.id_token").exists())
            .andReturn()
            .response
        val accessToken = jsonMapper.readTree(tokenResponse.contentAsString)["access_token"].stringValue()

        mockMvc.perform(get("/userinfo").header("Authorization", "Bearer $accessToken"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.sub").value("user-123"))
    }

    private fun loginRequest(username: String, password: String, tenantId: String) =
        post("/api/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                """
                {
                  "username": "$username",
                  "password": "$password",
                  "tenantId": "$tenantId"
                }
                """.trimIndent(),
            )

    private companion object {
        const val REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/client-123"
        const val CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        const val CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    }
}
