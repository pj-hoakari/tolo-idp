package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.ratelimit.RateLimitFilter
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertSame

@Tag("unit")
class RateLimitConfigTests {
    private val config = RateLimitConfig()

    @Test
    fun requiresARedisUriWhenRateLimitingIsEnabled() {
        for (uri in listOf(null, "", " ")) {
            val properties = IdpProperties(
                rateLimit = IdpProperties.RateLimit(
                    redis = IdpProperties.RateLimit.Redis(uri = uri),
                ),
            )

            val exception = assertFailsWith<IllegalStateException> {
                config.rateLimitRedisClient(properties)
            }

            assertEquals(
                "tolo-idp.rate-limit.redis.uri is required when rate limiting is enabled",
                exception.message,
            )
        }
    }

    @Test
    fun createsRedisClientForConfiguredUri() {
        val client = config.rateLimitRedisClient(
            IdpProperties(
                rateLimit = IdpProperties.RateLimit(
                    redis = IdpProperties.RateLimit.Redis(uri = "redis://localhost:6379"),
                ),
            ),
        )

        try {
            assertNotNull(client)
        } finally {
            client.shutdown()
        }
    }

    @Test
    fun disablesTheServletFilterRegistration() {
        val filter = mock(RateLimitFilter::class.java)

        val registration = config.rateLimitFilterRegistration(filter)

        assertFalse(registration.isEnabled)
        assertSame(filter, registration.filter)
    }
}
