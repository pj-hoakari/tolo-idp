package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.http.HttpServletRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import tools.jackson.databind.ObjectMapper
import kotlin.test.assertEquals
import kotlin.test.assertNull

@SpringBootTest
class RateLimitIdentityExtractorTests(
    @Autowired private val objectMapper: ObjectMapper,
) {
    private val extractor = RateLimitIdentityExtractor(objectMapper)

    @AfterEach
    fun tearDown() {
        SecurityContextHolder.clearContext()
    }

    @Test
    fun usesRemoteAddrAndIgnoresForwardedHeaders() {
        val request = MockHttpServletRequest("GET", "/actuator/health").apply {
            remoteAddr = "192.0.2.10"
            addHeader("X-Forwarded-For", "198.51.100.20")
        }

        val identity = extractor.identity(request)

        assertEquals("192.0.2.10", identity.ip)
        assertNull(identity.userId)
    }

    @Test
    fun usesAuthenticatedPrincipalNameAsUserId() {
        SecurityContextHolder.getContext().authentication =
            UsernamePasswordAuthenticationToken.authenticated("user-123", null, emptyList())
        val request = MockHttpServletRequest("GET", "/userinfo").apply {
            remoteAddr = "192.0.2.10"
        }

        val identity = extractor.identity(request)

        assertEquals("user-123", identity.userId)
    }

    @Test
    fun extractsLoginUsernameFromCachedJsonBody() {
        val request = loginRequest("""{"username":"user-123","password":"secret","tenantId":"tenant-a"}""")

        val identity = extractor.identity(CachedBodyHttpServletRequest(request))

        assertEquals("[\"tenant-a\",\"user-123\"]", identity.userId)
    }

    @Test
    fun loginRateLimitSeparatesTenantsAndRequiresTenantContext() {
        val first = extractor.identity(CachedBodyHttpServletRequest(loginRequest(
            """{"username":"same","tenantId":"tenant-a"}""")))
        val second = extractor.identity(CachedBodyHttpServletRequest(loginRequest(
            """{"username":"same","tenantId":"tenant-b"}""")))
        kotlin.test.assertNotEquals(first.userId, second.userId)
        assertNull(extractor.identity(CachedBodyHttpServletRequest(loginRequest(
            """{"username":"same"}"""))).userId)
    }

    @Test
    fun malformedLoginJsonFallsBackToIpOnly() {
        val request = loginRequest("""{"username":""")

        val identity = extractor.identity(CachedBodyHttpServletRequest(request))

        assertNull(identity.userId)
    }

    @Test
    fun tokenExchangeRequestDoesNotUseUnvalidatedJwtClaims() {
        val request = MockHttpServletRequest("POST", "/oauth2/token").apply {
            remoteAddr = "192.0.2.10"
            contentType = MediaType.APPLICATION_FORM_URLENCODED_VALUE
            addParameter("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
            addParameter("subject_token", "e30.eyJzdWIiOiJ1c2VyLTEyMyJ9.signature")
        }

        val identity = extractor.identity(request)

        assertNull(identity.userId)
    }

    private fun loginRequest(body: String): HttpServletRequest =
        MockHttpServletRequest("POST", "/api/login").apply {
            remoteAddr = "192.0.2.10"
            contentType = MediaType.APPLICATION_JSON_VALUE
            setContent(body.toByteArray())
        }
}
