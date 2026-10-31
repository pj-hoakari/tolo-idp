package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.user.IdpUserDetailsManager
import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.test.web.servlet.MockMvc
import dev.usbharu.toloidp.security.challengeFrom
import dev.usbharu.toloidp.security.loginWithChallenge
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
class CorsConfigTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
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
    fun loginPreflightAllowsTheLoginPageOriginWithCredentials() {
        mockMvc.perform(preflight("http://localhost:3000"))
            .andExpect(status().isOk)
            .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
            .andExpect(header().string("Access-Control-Allow-Credentials", "true"))
            .andExpect(header().string("Access-Control-Allow-Methods", "POST"))
            .andExpect(header().string("Access-Control-Allow-Headers", "content-type"))
    }

    @ParameterizedTest
    @ValueSource(strings = ["http://127.0.0.1:3000", "https://localhost:3000", "https://tenant-a.localhost:3000", "http://localhost:18080"])
    fun loginPreflightRejectsOtherOrigins(origin: String) {
        mockMvc.perform(preflight(origin))
            .andExpect(status().isForbidden)
            .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
    }

    @Test
    fun loginPreflightAllowsNoHeaderBeyondContentType() {
        mockMvc.perform(preflight("http://localhost:3000", "authorization"))
            .andExpect(status().isForbidden)
            .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
        mockMvc.perform(preflight("http://localhost:3000", "content-type, authorization"))
            .andExpect(header().string("Access-Control-Allow-Headers", "content-type"))
    }

    private fun preflight(origin: String, headers: String = "content-type") =
        options("/api/login")
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", headers)

    @Test
    fun loginPostIncludesCorsHeadersForConfiguredOrigin() {
        val challenge = mockMvc.challengeFrom(
            get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", "client-123")
                .queryParam("redirect_uri", "http://127.0.0.1:8080/login/oauth2/code/client-123")
                .queryParam("scope", "openid tenant.read").queryParam("resource", "https://api.example.com/tenants/tenant-a")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method", "S256"),
        )
        mockMvc.perform(
            loginWithChallenge(challenge)
                .header("Origin", "http://localhost:3000"),
        )
            .andExpect(status().isOk)
            .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
            .andExpect(header().string("Access-Control-Allow-Credentials", "true"))
    }
}
