package dev.usbharu.toloidp.ratelimit

import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import jakarta.servlet.ServletInputStream
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import tools.jackson.databind.ObjectMapper
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertNull

@SpringBootTest(properties = ["tolo-idp.rate-limit.enabled=false"])
@AutoConfigureMockMvc
class RateLimitFilterTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val rateLimitService: RecordingRateLimitService,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
) {
    @BeforeEach
    fun setUp() {
        rateLimitService.reset()
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
    fun ipOnlyRequestsAreRateLimited() {
        rateLimitService.nextDecision.set(
            RateLimitDecision(
                allowed = false,
                rejectedDimension = RateLimitDimension.IP,
                retryAfter = Duration.ofSeconds(3),
            ),
        )

        mockMvc.perform(get("/actuator/health").withRemoteAddr("192.0.2.10"))
            .andExpect(status().isTooManyRequests)
            .andExpect(header().string("Retry-After", "3"))
            .andExpect(jsonPath("$.error").value("rate_limited"))

        assertEquals(RateLimitIdentity("192.0.2.10", null), rateLimitService.lastIdentity.get())
    }

    @Test
    fun authenticatedRequestsUsePrincipalForUserDimensions() {
        mockMvc.perform(post("/api/logout").with(user("user-123")).withRemoteAddr("192.0.2.11"))
            .andExpect(status().isNoContent)

        assertEquals(RateLimitIdentity("192.0.2.11", "user-123"), rateLimitService.lastIdentity.get())
    }

    @Test
    fun loginRequestsUseUsernameAndStillReachController() {
        mockMvc.perform(
            post("/api/login")
                .withRemoteAddr("192.0.2.12")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "username": "user-123",
                      "password": "password",
                      "tenantId": "tenant-a"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.username").value("user-123"))

        assertEquals(RateLimitIdentity("192.0.2.12", "user-123"), rateLimitService.lastIdentity.get())
    }

    @Test
    fun oversizedLoginJsonIsRejectedBeforeRateLimit() {
        rateLimitService.unavailable.set(true)
        val body = ByteArray(OVERSIZED_LOGIN_BODY_BYTES)

        mockMvc.perform(
            post("/api/login")
                .withRemoteAddr("192.0.2.14")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body),
        )
            .andExpect(status().isPayloadTooLarge)
            .andExpect(jsonPath("$.error").value("payload_too_large"))

        assertNull(rateLimitService.lastIdentity.get())
    }

    @Test
    fun chunkedOversizedLoginJsonIsRejectedBeforeRateLimit() {
        rateLimitService.unavailable.set(true)
        val body = CountingServletInputStream(OVERSIZED_LOGIN_BODY_BYTES)

        mockMvc.perform(
            post("/api/login")
                .withRemoteAddr("192.0.2.15")
                .contentType(MediaType.APPLICATION_JSON)
                .with { request ->
                    UnboundedLoginBodyRequest(request, body)
                },
        )
            .andExpect(status().isPayloadTooLarge)
            .andExpect(jsonPath("$.error").value("payload_too_large"))

        assertNull(rateLimitService.lastIdentity.get())
        assertEquals(CachedBodyHttpServletRequest.MAX_LOGIN_JSON_BYTES + 1, body.bytesRead)
    }

    @Test
    fun redisFailureReturnsServiceUnavailable() {
        rateLimitService.unavailable.set(true)

        mockMvc.perform(get("/actuator/health").withRemoteAddr("192.0.2.13"))
            .andExpect(status().isServiceUnavailable)
            .andExpect(jsonPath("$.error").value("rate_limit_unavailable"))
    }

    @TestConfiguration
    class Config {
        @Bean
        fun recordingRateLimitService(): RecordingRateLimitService =
            RecordingRateLimitService()

        @Bean
        fun rateLimitIdentityExtractor(objectMapper: ObjectMapper): RateLimitIdentityExtractor =
            RateLimitIdentityExtractor(objectMapper)

        @Bean
        fun rateLimitFilter(
            identityExtractor: RateLimitIdentityExtractor,
            rateLimitService: RecordingRateLimitService,
        ): RateLimitFilter =
            RateLimitFilter(identityExtractor, rateLimitService)

        @Bean
        fun rateLimitFilterRegistration(rateLimitFilter: RateLimitFilter): FilterRegistrationBean<RateLimitFilter> =
            FilterRegistrationBean(rateLimitFilter).apply {
                isEnabled = false
            }
    }
}

class RecordingRateLimitService : RateLimitService {
    val lastIdentity = AtomicReference<RateLimitIdentity?>()
    val nextDecision = AtomicReference(RateLimitDecision(allowed = true))
    val unavailable = AtomicReference(false)

    override fun consume(identity: RateLimitIdentity): RateLimitDecision {
        lastIdentity.set(identity)
        if (unavailable.get()) {
            throw RateLimitUnavailableException("test unavailable")
        }
        return nextDecision.get()
    }

    fun reset() {
        lastIdentity.set(null)
        nextDecision.set(RateLimitDecision(allowed = true))
        unavailable.set(false)
    }
}

private const val OVERSIZED_LOGIN_BODY_BYTES = 2 * 1024 * 1024 + 1024

private class UnboundedLoginBodyRequest(
    delegate: MockHttpServletRequest,
    private val body: ServletInputStream,
) : MockHttpServletRequest(delegate.method, delegate.requestURI) {
    init {
        contentType = delegate.contentType
        remoteAddr = delegate.remoteAddr
        servletPath = delegate.servletPath
        contextPath = delegate.contextPath
        pathInfo = delegate.pathInfo
        characterEncoding = delegate.characterEncoding
    }

    override fun getContentLength(): Int = -1

    override fun getContentLengthLong(): Long = -1

    override fun getInputStream(): ServletInputStream = body
}

private fun <T : org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder> T.withRemoteAddr(
    remoteAddr: String,
): T {
    requestAttr("remoteAddr", remoteAddr)
    with { request ->
        request.remoteAddr = remoteAddr
        request
    }
    return this
}
