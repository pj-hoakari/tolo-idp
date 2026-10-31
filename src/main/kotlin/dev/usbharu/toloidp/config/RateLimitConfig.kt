package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.ratelimit.Bucket4jRedisRateLimitService
import dev.usbharu.toloidp.ratelimit.RateLimitFilter
import dev.usbharu.toloidp.ratelimit.RateLimitIdentityExtractor
import dev.usbharu.toloidp.ratelimit.RateLimitService
import dev.usbharu.toloidp.security.LoginChallenges
import io.github.bucket4j.distributed.proxy.ProxyManager
import io.github.bucket4j.redis.lettuce.Bucket4jLettuce
import io.lettuce.core.RedisClient
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import tools.jackson.databind.ObjectMapper

@Configuration
@ConditionalOnProperty(prefix = "tolo-idp.rate-limit", name = ["enabled"], havingValue = "true", matchIfMissing = true)
class RateLimitConfig {
    @Bean(destroyMethod = "shutdown")
    fun rateLimitRedisClient(properties: IdpProperties): RedisClient {
        val uri = properties.rateLimit.redis.uri
            ?.takeIf { it.isNotBlank() }
            ?: throw IllegalStateException("tolo-idp.rate-limit.redis.uri is required when rate limiting is enabled")
        return RedisClient.create(uri)
    }

    @Bean
    fun rateLimitProxyManager(redisClient: RedisClient): ProxyManager<ByteArray> =
        Bucket4jLettuce.casBasedBuilder(redisClient).build()

    @Bean
    fun rateLimitService(
        proxyManager: ProxyManager<ByteArray>,
        properties: IdpProperties,
    ): RateLimitService =
        Bucket4jRedisRateLimitService(proxyManager, properties)

    @Bean
    fun rateLimitIdentityExtractor(objectMapper: ObjectMapper, challenges: LoginChallenges): RateLimitIdentityExtractor =
        RateLimitIdentityExtractor(objectMapper, challenges::tenant)

    @Bean
    fun rateLimitFilter(
        identityExtractor: RateLimitIdentityExtractor,
        rateLimitService: RateLimitService,
    ): RateLimitFilter =
        RateLimitFilter(identityExtractor, rateLimitService)

    @Bean
    fun rateLimitFilterRegistration(rateLimitFilter: RateLimitFilter): FilterRegistrationBean<RateLimitFilter> =
        FilterRegistrationBean(rateLimitFilter).apply {
            isEnabled = false
        }
}
