package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicyConfig
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource as SpringResource
import java.net.URI
import java.time.Duration

@ConfigurationProperties(prefix = "tolo-idp", ignoreUnknownFields = false)
data class IdpProperties(
    val issuer: String = "http://localhost:8080",
    val resource: Resource = Resource(),
    val relation: Relation = Relation(),
    val seed: Seed = Seed(),
    val jwk: Jwk = Jwk(),
    val rateLimit: RateLimit = RateLimit(),
    val login: Login = Login(),
    val clients: Map<String, ClientPolicyConfig> = emptyMap(),
) {
    data class Login(
        val pageUrl: String = "",
        val errorPageUrl: String = "",
    ) {
        fun pageUri(): URI = webUri(pageUrl, "page-url")

        fun errorPageUri(): URI = webUri(errorPageUrl, "error-page-url")

        fun origin(): String = pageUri().let { "${it.scheme}://${it.rawAuthority}" }

        private fun webUri(value: String, name: String): URI {
            val uri = runCatching { URI(value) }.getOrNull()
            require(uri != null && uri.scheme in setOf("http", "https") && !uri.host.isNullOrEmpty() &&
                uri.rawUserInfo == null && uri.rawFragment == null) {
                "Configure tolo-idp.login.$name as an absolute http(s) URL"
            }
            return uri
        }
    }

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
