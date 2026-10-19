package dev.usbharu.toloidp.config

import org.junit.jupiter.api.Test
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor
import org.springframework.core.env.ConfigurableEnvironment
import org.springframework.core.env.StandardEnvironment
import org.springframework.core.io.DefaultResourceLoader
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DevelopmentProfileTests {
    @Test
    fun nativeProfileLoadsSharedDevelopmentSettingsAndContainerEndpoints() {
        val environment = loadProfile("dev-native")

        assertSharedDevelopmentSettings(environment, "dev-native")
        assertEquals("jdbc:postgresql://db:5432/tolo_idp", environment.getProperty("spring.datasource.url"))
        assertEquals("http://relation-stub:8080", environment.getProperty("tolo-idp.relation.base-url"))
        assertEquals("redis://redis:6379", environment.getProperty("tolo-idp.rate-limit.redis.uri"))
    }

    @Test
    fun productionProfileDisablesDevelopmentSettings() {
        val environment = loadProfile("production")

        assertEquals(listOf("production"), environment.activeProfiles.toList())
        assertEquals("false", environment.getProperty("tolo-idp.seed.enabled"))
        assertEquals("false", environment.getProperty("tolo-idp.jwk.allow-ephemeral"))
        assertEquals("org.postgresql.Driver", environment.getProperty("spring.datasource.driver-class-name"))
        assertEquals("classpath:db/postgresql", environment.getProperty("spring.flyway.locations"))
        assertNull(
            environment.getProperty(
                "spring.security.oauth2.authorizationserver.client.client-123.registration.client-id",
            ),
        )
        assertNull(environment.getProperty("tolo-idp.cors.allowed-origins[0]"))
    }

    @Test
    fun jvmProfileLoadsSharedDevelopmentSettingsAndContainerEndpoints() {
        val environment = loadProfile("dev-jvm")

        assertSharedDevelopmentSettings(environment, "dev-jvm")
        assertEquals("jdbc:postgresql://db:5432/tolo_idp", environment.getProperty("spring.datasource.url"))
        assertEquals("http://relation-stub:8080", environment.getProperty("tolo-idp.relation.base-url"))
        assertEquals("redis://redis:6379", environment.getProperty("tolo-idp.rate-limit.redis.uri"))
    }

    @Test
    fun nativeDevelopmentSettingsOverrideProductionProfileRecordedByAot() {
        val environment = loadProfile("production", "dev-native")

        assertEquals("true", environment.getProperty("tolo-idp.seed.enabled"))
        assertEquals("true", environment.getProperty("tolo-idp.jwk.allow-ephemeral"))
        assertEquals("http://localhost:18080", environment.getProperty("tolo-idp.issuer"))
        assertEquals(
            "client-123",
            environment.getProperty(
                "spring.security.oauth2.authorizationserver.client.client-123.registration.client-id",
            ),
        )
    }

    private fun loadProfile(vararg profiles: String): ConfigurableEnvironment {
        val environment = StandardEnvironment()
        // Ignore host SPRING_PROFILES_ACTIVE so only [profiles] are activated.
        environment.propertySources.remove("systemEnvironment")
        // Use the main YAML file only, excluding application.properties in test resources.
        // spring.config.location must be visible during ConfigData bootstrap; clear it afterward so
        // it does not leak to other tests in the same JVM.
        val configLocationKey = "spring.config.location"
        val previousConfigLocation = System.getProperty(configLocationKey)
        System.setProperty(configLocationKey, "classpath:/application.yaml")
        try {
            ConfigDataEnvironmentPostProcessor.applyTo(
                environment,
                DefaultResourceLoader(javaClass.classLoader),
                null,
                profiles.toList(),
            )
        } finally {
            if (previousConfigLocation == null) {
                System.clearProperty(configLocationKey)
            } else {
                System.setProperty(configLocationKey, previousConfigLocation)
            }
        }
        return environment
    }

    private fun assertSharedDevelopmentSettings(environment: ConfigurableEnvironment, profile: String) {
        assertTrue(profile in environment.activeProfiles)
        assertEquals(listOf(profile), environment.activeProfiles.toList())
        assertEquals("http://localhost:18080", environment.getProperty("tolo-idp.issuer"))
        assertEquals("true", environment.getProperty("tolo-idp.seed.enabled"))
        assertEquals(
            "client-123",
            environment.getProperty(
                "spring.security.oauth2.authorizationserver.client.client-123.registration.client-id",
            ),
        )
        assertEquals(
            "15m",
            environment.getProperty(
                "spring.security.oauth2.authorizationserver.client.client-123.token.access-token-time-to-live",
            ),
        )
        assertEquals("true", environment.getProperty("tolo-idp.jwk.allow-ephemeral"))
        assertEquals("org.postgresql.Driver", environment.getProperty("spring.datasource.driver-class-name"))
        assertEquals("classpath:db/postgresql", environment.getProperty("spring.flyway.locations"))
    }
}
