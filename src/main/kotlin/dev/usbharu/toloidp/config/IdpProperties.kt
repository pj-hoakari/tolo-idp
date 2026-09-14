package dev.usbharu.toloidp.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource as SpringResource
import java.time.Duration

@ConfigurationProperties(prefix = "tolo-idp")
data class IdpProperties(
    val issuer: String = "http://localhost:8080",
    val resource: Resource = Resource(),
    val relation: Relation = Relation(),
    val token: Token = Token(),
    val seed: Seed = Seed(),
    val jwk: Jwk = Jwk(),
    val rateLimit: RateLimit = RateLimit(),
    val cors: Cors = Cors(),
) {
    data class Cors(
        val allowedOrigins: Set<String> = emptySet(),
    )
    data class Resource(
        val allowedHosts: Set<String> = setOf("api.example.com"),
    )

    data class Relation(
        val baseUrl: String = "http://localhost:8081",
        val connectTimeout: Duration = Duration.ofSeconds(2),
        val readTimeout: Duration = Duration.ofSeconds(3),
        val cache: Cache = Cache(),
    ) {
        data class Cache(
            val ttl: Duration = Duration.ofMinutes(5),
            val adminSubjects: Set<String> = emptySet(),
        )
    }

    data class Token(
        val tenantAccessTtl: Duration = Duration.ofMinutes(15),
        val eventAccessTtl: Duration = Duration.ofMinutes(10),
    )

    data class Seed(
        val enabled: Boolean = false,
        val clientSecret: String = "secret",
        val userPassword: String = "password",
    )

    data class Jwk(
        val privateKeyPem: String? = null,
        val privateKeyLocation: SpringResource? = null,
        val keyId: String? = null,
        val allowEphemeral: Boolean = false,
    )

    data class RateLimit(
        val enabled: Boolean = true,
        val redis: Redis = Redis(),
        val ip: Limit = Limit(capacity = 60, refillPeriod = Duration.ofMinutes(1)),
        val user: Limit = Limit(capacity = 30, refillPeriod = Duration.ofMinutes(1)),
        val ipUser: Limit = Limit(capacity = 20, refillPeriod = Duration.ofMinutes(1)),
    ) {
        data class Redis(
            val uri: String? = null,
            val keyPrefix: String = "tolo-idp:rate-limit",
        )

        data class Limit(
            val capacity: Long,
            val refillPeriod: Duration,
        )
    }
}
