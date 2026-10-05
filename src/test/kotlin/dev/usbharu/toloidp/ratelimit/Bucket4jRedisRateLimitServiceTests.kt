package dev.usbharu.toloidp.ratelimit

import dev.usbharu.toloidp.config.IdpProperties
import io.github.bucket4j.Bucket
import io.github.bucket4j.BucketConfiguration
import io.github.bucket4j.ConsumptionProbe
import io.github.bucket4j.EstimationProbe
import io.github.bucket4j.TimeMeter
import io.github.bucket4j.distributed.BucketProxy
import io.github.bucket4j.distributed.proxy.ProxyManager
import org.junit.jupiter.api.Test
import org.mockito.AdditionalAnswers.delegatesTo
import org.mockito.Mockito.mock
import org.mockito.stubbing.Answer
import java.time.Duration
import java.util.function.Supplier
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class Bucket4jRedisRateLimitServiceTests {
    @Test
    fun anonymousRequestsShareAnIpBucketAndRefillAfterTheConfiguredPeriod() {
        val fixture = Fixture(ipCapacity = 2)
        val identity = RateLimitIdentity("192.0.2.1", null)

        repeat(2) { assertTrue(fixture.service.consume(identity).allowed) }
        assertEquals(
            RateLimitDecision(false, RateLimitDimension.IP, Duration.ofMinutes(1).dividedBy(2)),
            fixture.service.consume(identity),
        )
        assertEquals(1, fixture.buckets.size)

        fixture.nowNanos += Duration.ofMinutes(1).toNanos()
        assertTrue(fixture.service.consume(identity).allowed)
    }

    @Test
    fun authenticatedRequestsConsumeAllDimensionsAndDoNotStoreRawIdentitiesInKeys() {
        val fixture = Fixture(ipCapacity = 4, userCapacity = 3, ipUserCapacity = 2)

        assertTrue(fixture.service.consume(RateLimitIdentity("192.0.2.1", "user-123")).allowed)

        assertEquals(3, fixture.buckets.size)
        assertEquals(setOf("ip_user", "user", "ip"), fixture.buckets.keys.map { it.split(':')[1] }.toSet())
        assertTrue(fixture.buckets.keys.all { it.matches(Regex("scenario:(ip_user|user|ip):[A-Za-z0-9_-]{43}")) })
        assertEquals(setOf(3L, 2L, 1L), fixture.buckets.values.map { it.availableTokens }.toSet())
    }

    @Test
    fun ipUserLimitRejectsWithoutConsumingOtherDimensions() {
        val fixture = Fixture(ipCapacity = 4, userCapacity = 3, ipUserCapacity = 1)
        val identity = RateLimitIdentity("192.0.2.1", "user-123")
        assertTrue(fixture.service.consume(identity).allowed)
        val before = fixture.buckets.mapValues { it.value.availableTokens }

        val decision = fixture.service.consume(identity)

        assertFalse(decision.allowed)
        assertEquals(RateLimitDimension.IP_USER, decision.rejectedDimension)
        assertEquals(Duration.ofMinutes(1), decision.retryAfter)
        assertEquals(before, fixture.buckets.mapValues { it.value.availableTokens })
        assertTrue(fixture.service.consume(identity.copy(ip = "192.0.2.2")).allowed)
    }

    @Test
    fun userLimitIsSharedAcrossIpAddresses() {
        val fixture = Fixture(userCapacity = 1)
        assertTrue(fixture.service.consume(RateLimitIdentity("192.0.2.1", "user-123")).allowed)

        val decision = fixture.service.consume(RateLimitIdentity("192.0.2.2", "user-123"))

        assertFalse(decision.allowed)
        assertEquals(RateLimitDimension.USER, decision.rejectedDimension)
        assertEquals(Duration.ofMinutes(1), decision.retryAfter)
        assertTrue(fixture.service.consume(RateLimitIdentity("192.0.2.2", "user-456")).allowed)
    }

    @Test
    fun ipLimitIsSharedAcrossUsersAndRejectedRequestsDoNotConsumeUserBuckets() {
        val fixture = Fixture(ipCapacity = 1)
        assertTrue(fixture.service.consume(RateLimitIdentity("192.0.2.1", "user-123")).allowed)

        val decision = fixture.service.consume(RateLimitIdentity("192.0.2.1", "user-456"))

        assertFalse(decision.allowed)
        assertEquals(RateLimitDimension.IP, decision.rejectedDimension)
        assertEquals(Duration.ofMinutes(1), decision.retryAfter)
        assertEquals(2, fixture.buckets.values.count { it.availableTokens == 10L })
        assertTrue(fixture.service.consume(RateLimitIdentity("192.0.2.2", "user-456")).allowed)
    }

    @Test
    fun consumptionRaceReturnsRejectionEvenWhenEstimationSucceeded() {
        val bucket = mock(BucketProxy::class.java, Answer { invocation ->
            when (invocation.method.name) {
                "estimateAbilityToConsume" -> EstimationProbe.canBeConsumed(1)
                "tryConsumeAndReturnRemaining" -> ConsumptionProbe.rejected(0, 123, 123)
                else -> throw UnsupportedOperationException(invocation.method.name)
            }
        })
        val manager = proxyManager(Answer { bucket })
        val service = Bucket4jRedisRateLimitService(manager, IdpProperties())

        assertEquals(
            RateLimitDecision(false, RateLimitDimension.IP, Duration.ofNanos(123)),
            service.consume(RateLimitIdentity("192.0.2.1", null)),
        )
    }

    @Test
    fun backendFailureIsReportedAsUnavailableWithItsOriginalCause() {
        val cause = IllegalStateException("backend unavailable")
        val manager = proxyManager(Answer { throw cause })
        val service = Bucket4jRedisRateLimitService(manager, IdpProperties())

        val error = assertFailsWith<RateLimitUnavailableException> {
            service.consume(RateLimitIdentity("192.0.2.1", "user-123"))
        }

        assertSame(cause, error.cause)
    }

    /** Use real Bucket4j buckets and a fixed clock; substitute only the Redis transport. */
    private class Fixture(
        ipCapacity: Long = 10,
        userCapacity: Long = 10,
        ipUserCapacity: Long = 10,
    ) {
        var nowNanos = 0L
        val buckets = mutableMapOf<String, Bucket>()
        private val proxies = mutableMapOf<String, BucketProxy>()
        private val timeMeter = object : TimeMeter {
            override fun currentTimeNanos(): Long = nowNanos
            override fun isWallClockBased(): Boolean = false
        }
        private val manager = proxyManager(Answer { invocation ->
            check(invocation.method.name == "getProxy")
            val key = String(invocation.getArgument<ByteArray>(0), Charsets.UTF_8)
            val configuration = invocation.getArgument<Supplier<BucketConfiguration>>(1).get()
            proxies.getOrPut(key) {
                val builder = Bucket.builder().withCustomTimePrecision(timeMeter)
                configuration.bandwidths.forEach { builder.addLimit(it) }
                val bucket = builder.build()
                buckets[key] = bucket
                mock(BucketProxy::class.java, delegatesTo<BucketProxy>(bucket))
            }
        })
        val service = Bucket4jRedisRateLimitService(
            manager,
            IdpProperties(
                rateLimit = IdpProperties.RateLimit(
                    redis = IdpProperties.RateLimit.Redis(keyPrefix = "scenario::"),
                    ip = limit(ipCapacity),
                    user = limit(userCapacity),
                    ipUser = limit(ipUserCapacity),
                ),
            ),
        )
    }

    companion object {
        private fun limit(capacity: Long) = IdpProperties.RateLimit.Limit(capacity, Duration.ofMinutes(1))

        @Suppress("UNCHECKED_CAST")
        private fun proxyManager(answer: Answer<Any>): ProxyManager<ByteArray> =
            mock(ProxyManager::class.java, answer) as ProxyManager<ByteArray>
    }
}
