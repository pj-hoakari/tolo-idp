package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.*
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.json.JsonMapper
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:tenant-user-flow;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
@AutoConfigureMockMvc
class TenantScopedUserFlowTests(
    @Autowired private val mvc: MockMvc,
    @Autowired private val users: IdpUserDetailsManager,
    @Autowired private val cache: RelationMembershipCacheRepository,
    @Autowired private val decoder: JwtDecoder,
    @Autowired private val json: JsonMapper,
) {
    @Test
    fun sameLoginNameHasIndependentCredentialsSubjectsAndRelationLookups() {
        for ((tenant, password) in listOf("tenant-a" to "password-a", "tenant-b" to "password-b")) {
            users.createUser(tenant, User.withUsername("same-login").password("{noop}$password").roles("USER").build())
            cache.save(RelationMembershipCache(
                cacheId = RelationMembershipCacheId(tenant, "same-login"),
                membership = TenantMembership(tenant, RelationRole.OWNER, listOf(EventMembership("event-1", RelationRole.STAFF))),
                cachedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(300),
            ))
        }
        try {
            val a = users.loadUserByUsername("tenant-a", "same-login")
            val b = users.loadUserByUsername("tenant-b", "same-login")
            assertNotEquals(a.id, b.id)
            mvc.perform(login("tenant-a", "password-b")).andExpect(status().isUnauthorized)
            mvc.perform(login("tenant-b", "password-a")).andExpect(status().isUnauthorized)
            mvc.perform(login("tenant-c", "password-a")).andExpect(status().isUnauthorized)
            for ((tenant, password, subject) in listOf(Triple("tenant-a", "password-a", a.id), Triple("tenant-b", "password-b", b.id))) {
                val session = mvc.perform(login(tenant, password)).andExpect(status().isOk)
                    .andExpect(jsonPath("$.sub").value(subject)).andReturn().request.session as MockHttpSession
                // A session from one tenant must not authorize a resource in the other tenant.
                val otherTenant = if (tenant == "tenant-a") "tenant-b" else "tenant-a"
                session.setAttribute(dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE, otherTenant)
                try {
                    mvc.perform(authorize(session, otherTenant))
                        .andExpect(status().isBadRequest)
                } finally {
                    session.setAttribute(dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE, tenant)
                }
                val location = mvc.perform(authorize(session, tenant)).andExpect(status().isFound).andReturn().response.redirectedUrl!!
                val code = UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code")!!
                val issued = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
                    .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", REDIRECT)
                    .param("code_verifier", VERIFIER))
                    .andExpect(status().isOk).andReturn().response.contentAsString
                val tokens = json.readTree(issued)
                val access = tokens["access_token"].stringValue()
                assertEquals(subject, decoder.decode(access).subject)
                assertEquals(subject, decoder.decode(tokens["id_token"].stringValue()).subject)
                assertEquals(tenant, decoder.decode(access).getClaimAsString("tenant_id"))
                mvc.perform(get("/userinfo").header("Authorization", "Bearer $access"))
                    .andExpect(status().isOk).andExpect(jsonPath("$.sub").value(subject))
                    .andExpect(jsonPath("$.preferred_username").value("same-login"))
                val refreshed = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
                    .param("grant_type", "refresh_token").param("refresh_token", tokens["refresh_token"].stringValue()))
                    .andExpect(status().isOk).andReturn().response.contentAsString
                val refreshedAccess = json.readTree(refreshed)["access_token"].stringValue()
                assertEquals(subject, decoder.decode(refreshedAccess).subject)
                val event = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
                    .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                    .param("subject_token", refreshedAccess).param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                    .param("audience", "backend-api").param("resource", "https://api.example.com/tenants/$tenant/events/event-1")
                    .param("scope", "events.read"))
                    .andExpect(status().isOk).andReturn().response.contentAsString
                assertEquals(subject, decoder.decode(json.readTree(event)["access_token"].stringValue()).subject)
            }
        } finally {
            users.deleteUser("tenant-a", "same-login")
            users.deleteUser("tenant-b", "same-login")
            cache.deleteAll()
        }
    }

    private fun login(tenant: String, password: String) = post("/api/login").contentType(MediaType.APPLICATION_JSON)
        .content("""{"tenantId":"$tenant","username":"same-login","password":"$password"}""")

    private fun authorize(session: MockHttpSession, tenant: String) = get("/oauth2/authorize").session(session)
        .queryParam("response_type", "code").queryParam("client_id", "client-123").queryParam("redirect_uri", REDIRECT)
        .queryParam("scope", "openid profile tenant.read events.read").queryParam("audience", "backend-api")
        .queryParam("resource", "https://api.example.com/tenants/$tenant")
        .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method", "S256")

    companion object {
        private const val REDIRECT = "http://127.0.0.1:8080/login/oauth2/code/client-123"
        private const val VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    }
}
