package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import tools.jackson.databind.json.JsonMapper
import kotlin.test.assertEquals

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:authorization-request-split;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
@AutoConfigureMockMvc
class AuthorizationRequestParameterSplitTests(
    @Autowired private val mvc: MockMvc,
    @Autowired private val challenges: LoginChallenges,
    @Autowired private val json: JsonMapper,
) {
    @Test
    fun postAuthorizationRequestCannotMixQueryAndFormParameters() {
        mvc.perform(
            post("/oauth2/authorize?scope=tenant.join")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("response_type", "code")
                .param("client_id", "audit-no-join")
                .param("redirect_uri", "http://127.0.0.1:8080/audit/callback")
                .param("state", "request-state")
                .param("audience", "backend-api")
                .param("resource", "https://api.example.com/tenants/tenant-z"),
        )
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("http://localhost:3000/auth/error?error=invalid_request"))
    }

    @Test
    fun signupRejectsARegistrationChallengeIssuedToAClientWithoutTenantJoin() {
        val challenge = challenges.issue(
            "audit-no-join",
            "tenant-z",
            mapOf("scope" to arrayOf("tenant.join")),
            registration = true,
        )!!
        val body = json.writeValueAsString(mapOf(
            "username" to "split-test-user",
            "password" to "password123",
            "challenge" to challenge,
        ))
        val result = mvc.perform(
            post("/api/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body),
        )
            .andExpect(status().isBadRequest)
            .andReturn()
        assertEquals(400, result.response.status)
    }
}
