package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.doAnswer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.MvcResult
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:signup-concurrency;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
@AutoConfigureMockMvc
class SignupConcurrencyTests(
    @Autowired private val mvc: MockMvc,
    @Autowired private val users: IdpUserDetailsManager,
    @Autowired private val jdbc: JdbcTemplate,
) {
    @MockitoSpyBean private lateinit var encoder: PasswordEncoder

    @Test
    fun failedConcurrentSignupDoesNotCreateAnAccount() {
        val tenant = "race-${UUID.randomUUID()}"
        val challenge = registrationChallenge(tenant)
        val barrier = CyclicBarrier(2)
        // Both requests must pass challenge validation before either creates a user.
        doAnswer { call ->
            barrier.await(10, TimeUnit.SECONDS)
            call.callRealMethod()
        }.`when`(encoder).encode(anyString())
        val pool = Executors.newFixedThreadPool(2)
        try {
            val responses = (1..2).map { i ->
                pool.submit<MvcResult> {
                    mvc.perform(post("/api/signup").contentType(MediaType.APPLICATION_JSON)
                        .content("""{"username":"racer-$i","password":"correct horse","challenge":"$challenge"}"""))
                        .andReturn()
                }
            }.map { it.get(20, TimeUnit.SECONDS) }
            assertEquals(listOf(201, 400), responses.map { it.response.status }.sorted())
            val rejected = responses.single { it.response.status == 400 }
            assertNull(rejected.request.getSession(false)?.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY))
            val persisted = (1..2).count { users.userExists(tenant, "racer-$it") }
            assertEquals(1, persisted, "Only the successful signup should persist an account")
            val created = responses.single { it.response.status == 201 }
            val session = created.request.session as MockHttpSession
            val location = mvc.perform(resumeAuthorization(challenge, session)).andExpect(status().isFound)
                .andReturn().response.redirectedUrl!!
            assertTrue(location.startsWith("http://127.0.0.1:8080/login/oauth2/code/client-123?code="))
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun challengeExpiringDuringSignupDoesNotLeaveAUserOrSession() {
        val tenant = "expiry-${UUID.randomUUID()}"
        val challenge = registrationChallenge(tenant)
        doAnswer { call ->
            jdbc.update("UPDATE idp_login_challenge SET expires_at = ? WHERE tenant_id = ?", Timestamp.from(Instant.EPOCH), tenant)
            call.callRealMethod()
        }.`when`(encoder).encode(anyString())
        val result = mvc.perform(post("/api/signup").contentType(MediaType.APPLICATION_JSON)
            .content("""{"username":"expired-user","password":"correct horse","challenge":"$challenge"}"""))
            .andExpect(status().isBadRequest).andReturn()
        assertFalse(users.userExists(tenant, "expired-user"))
        assertNull(result.request.getSession(false)?.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY))
    }

    private fun registrationChallenge(tenant: String): String =
        mvc.challengeFrom(get("/oauth2/authorize")
            .queryParam("response_type", "code").queryParam("client_id", "client-123")
            .queryParam("redirect_uri", "http://127.0.0.1:8080/login/oauth2/code/client-123")
            .queryParam("scope", "tenant.join").queryParam("resource", "https://api.example.com/tenants/$tenant")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .queryParam("code_challenge_method", "S256"))
}
