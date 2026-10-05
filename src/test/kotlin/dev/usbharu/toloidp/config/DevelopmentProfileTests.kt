package dev.usbharu.toloidp.config

import org.junit.jupiter.api.Test
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor
import org.springframework.core.env.MapPropertySource
import org.springframework.core.env.StandardEnvironment
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DevelopmentProfileTests {
    @Test
    fun nativeProfileLoadsSharedDevelopmentSettingsAndContainerEndpoints() {
        val environment = loadProfile("dev.native")

        assertSharedDevelopmentSettings(environment, "dev.native")
        assertEquals("jdbc:postgresql://db:5432/tolo_idp", environment.getProperty("spring.datasource.url"))
        assertEquals("http://relation-stub:8080", environment.getProperty("tolo-idp.relation.base-url"))
        assertEquals("redis://redis:6379", environment.getProperty("tolo-idp.rate-limit.redis.uri"))
    }

    @Test
    fun jvmProfileLoadsSharedDevelopmentSettingsAndHostEndpoints() {
        val environment = loadProfile("dev.jvm")

        assertSharedDevelopmentSettings(environment, "dev.jvm")
        assertEquals("jdbc:postgresql://localhost:15432/tolo_idp", environment.getProperty("spring.datasource.url"))
        assertEquals("http://localhost:18081", environment.getProperty("tolo-idp.relation.base-url"))
        assertEquals("redis://localhost:16379", environment.getProperty("tolo-idp.rate-limit.redis.uri"))
    }

    private fun loadProfile(profile: String): StandardEnvironment = StandardEnvironment().apply {
        // Use the main YAML files only, excluding application.properties in test resources.
        propertySources.addFirst(
            MapPropertySource(
                "development-profile-test",
                mapOf(
                    "spring.config.location" to "classpath:/application.yaml",
                    "spring.profiles.active" to profile,
                ),
            ),
        )
        ConfigDataEnvironmentPostProcessor.applyTo(this)
    }

    private fun assertSharedDevelopmentSettings(environment: StandardEnvironment, profile: String) {
        assertTrue(profile in environment.activeProfiles)
        assertTrue("dev" in environment.activeProfiles)
        assertEquals("http://localhost:18080", environment.getProperty("tolo-idp.issuer"))
        assertEquals("true", environment.getProperty("tolo-idp.seed.enabled"))
        assertEquals("true", environment.getProperty("tolo-idp.jwk.allow-ephemeral"))
        assertEquals("org.postgresql.Driver", environment.getProperty("spring.datasource.driver-class-name"))
        assertEquals("classpath:db/postgresql", environment.getProperty("spring.flyway.locations"))
    }
}
