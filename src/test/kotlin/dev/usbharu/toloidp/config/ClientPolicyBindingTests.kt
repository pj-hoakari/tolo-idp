package dev.usbharu.toloidp.config

import org.junit.jupiter.api.Test
import org.springframework.boot.context.properties.bind.BindException
import org.springframework.boot.context.properties.bind.BindHandler
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.boot.context.properties.bind.handler.NoUnboundElementsBindHandler
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ClientPolicyBindingTests {
    @Test
    fun bindsPolicyUsingTheRegistrationKeyAndDurationSyntax() {
        val properties = bind(mapOf(
            "tolo-idp.clients.web-app.allowed-audiences" to "backend-api",
            "tolo-idp.clients.web-app.event-access-ttl" to "45s",
            "tolo-idp.clients.gateway.allowed-audiences" to "backend-api",
            "tolo-idp.clients.gateway.token-introspection-allowed" to "true",
        ))
        val config = properties.clients.getValue("web-app")
        assertEquals(setOf("backend-api"), config.allowedAudiences)
        assertEquals(Duration.ofSeconds(45), config.eventAccessTtl)
        assertFalse(config.tokenIntrospectionAllowed)
        assertTrue(properties.clients.getValue("gateway").tokenIntrospectionAllowed)
    }

    @Test
    fun rejectsMisspelledPolicySettingsInsteadOfSilentlyUsingDefaults() {
        assertFailsWith<BindException> {
            bind(mapOf(
                "tolo-idp.clients.web-app.allowed-audiences" to "backend-api",
                "tolo-idp.clients.web-app.event-ttl" to "45s",
            ))
        }
    }

    // Exercise the same strict binder used by @ConfigurationProperties without
    // creating an application context dynamically at Native runtime.
    private fun bind(values: Map<String, String>): IdpProperties =
        Binder(MapConfigurationPropertySource(values)).bind(
            "tolo-idp",
            Bindable.of(IdpProperties::class.java),
            NoUnboundElementsBindHandler(BindHandler.DEFAULT),
        ).get()
}
