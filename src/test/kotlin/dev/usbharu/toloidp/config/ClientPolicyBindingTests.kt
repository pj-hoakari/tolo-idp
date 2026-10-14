package dev.usbharu.toloidp.config

import org.junit.jupiter.api.Test
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.Configuration
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ClientPolicyBindingTests {
    private val context = ApplicationContextRunner().withUserConfiguration(BindingConfiguration::class.java)

    @Test
    fun bindsPolicyUsingTheRegistrationKeyAndDurationSyntax() {
        context.withPropertyValues(
            "tolo-idp.clients.web-app.allowed-audiences=backend-api",
            "tolo-idp.clients.web-app.event-access-ttl=45s",
        ).run {
            assertNull(it.startupFailure)
            val config = it.getBean(IdpProperties::class.java).clients.getValue("web-app")
            assertEquals(setOf("backend-api"), config.allowedAudiences)
            assertEquals(Duration.ofSeconds(45), config.eventAccessTtl)
        }
    }

    @Test
    fun rejectsMisspelledPolicySettingsInsteadOfSilentlyUsingDefaults() {
        context.withPropertyValues(
            "tolo-idp.clients.web-app.allowed-audiences=backend-api",
            "tolo-idp.clients.web-app.event-ttl=45s",
        ).run { assertNotNull(it.startupFailure) }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(IdpProperties::class)
    class BindingConfiguration
}
