package dev.usbharu.toloidp.ratelimit

import dev.usbharu.toloidp.config.IdpProperties
import io.github.bucket4j.BucketConfiguration
import io.github.bucket4j.distributed.proxy.ProxyManager
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64
import java.util.function.Supplier

/**
 * Redis をバックエンドにして IP / user / IP-user 単位の bucket を評価する [RateLimitService]。
 *
 * Redis の bucket key へ生の IP アドレスや user ID を保存しないよう、identity はハッシュ化して使う。
 */
class Bucket4jRedisRateLimitService(
    private val proxyManager: ProxyManager<ByteArray>,
    properties: IdpProperties,
) : RateLimitService {
    private val keyPrefix = properties.rateLimit.redis.keyPrefix.trimEnd(':')
    private val ipConfiguration = bucketConfiguration(properties.rateLimit.ip)
    private val userConfiguration = bucketConfiguration(properties.rateLimit.user)
    private val ipUserConfiguration = bucketConfiguration(properties.rateLimit.ipUser)

    /**
     * 対象となるすべての bucket を消費前に確認し、拒否されるリクエストで一部の次元だけが
     * 消費されないようにする。
     */
    override fun consume(identity: RateLimitIdentity): RateLimitDecision {
        val checks = checks(identity)

        try {
            checks.forEach { check ->
                val probe = check.bucket().estimateAbilityToConsume(1)
                if (!probe.canBeConsumed()) {
                    return RateLimitDecision(
                        allowed = false,
                        rejectedDimension = check.dimension,
                        retryAfter = Duration.ofNanos(probe.nanosToWaitForRefill),
                    )
                }
            }

            checks.forEach { check ->
                val probe = check.bucket().tryConsumeAndReturnRemaining(1)
                if (!probe.isConsumed) {
                    return RateLimitDecision(
                        allowed = false,
                        rejectedDimension = check.dimension,
                        retryAfter = Duration.ofNanos(probe.nanosToWaitForRefill),
                    )
                }
            }
            return RateLimitDecision(allowed = true)
        } catch (ex: RuntimeException) {
            throw RateLimitUnavailableException("Rate limit backend is unavailable", ex)
        }
    }

    private fun checks(identity: RateLimitIdentity): List<BucketCheck> {
        val userId = identity.userId
        val checks = mutableListOf<BucketCheck>()
        // Check the shared IP bucket first: a denied request must not materialize
        // caller-selected user or IP_USER buckets in the shared Redis store.
        checks += BucketCheck(
            dimension = RateLimitDimension.IP,
            key = key("ip", identity.ip),
            configuration = ipConfiguration,
        )
        if (userId != null) {
            checks += BucketCheck(
                dimension = RateLimitDimension.IP_USER,
                key = key("ip_user", "${identity.ip}\u001f$userId"),
                configuration = ipUserConfiguration,
            )
            checks += BucketCheck(
                dimension = RateLimitDimension.USER,
                key = key("user", userId),
                configuration = userConfiguration,
            )
        }
        return checks
    }

    private fun BucketCheck.bucket() =
        proxyManager.getProxy(key, Supplier { configuration })

    private fun key(dimension: String, rawIdentity: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(rawIdentity.toByteArray(StandardCharsets.UTF_8))
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        return "$keyPrefix:$dimension:$encoded".toByteArray(StandardCharsets.UTF_8)
    }

    private fun bucketConfiguration(limit: IdpProperties.RateLimit.Limit): BucketConfiguration =
        BucketConfiguration.builder()
            .addLimit { bandwidth ->
                bandwidth.capacity(limit.capacity).refillGreedy(limit.capacity, limit.refillPeriod)
            }
            .build()

    private data class BucketCheck(
        val dimension: RateLimitDimension,
        val key: ByteArray,
        val configuration: BucketConfiguration,
    )
}
