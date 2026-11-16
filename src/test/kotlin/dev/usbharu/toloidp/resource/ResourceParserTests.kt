package dev.usbharu.toloidp.resource

import org.junit.jupiter.api.Tag
import dev.usbharu.toloidp.config.IdpProperties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@Tag("unit")
class ResourceParserTests {
    private val parser = ResourceParser(
        IdpProperties(resource = IdpProperties.Resource(allowedHosts = setOf("api.example.com"))),
    )

    @Test
    fun parsesTenantResource() {
        val resource = parser.parseTenant("https://api.example.com/tenants/tenant-a")
        assertEquals("tenant-a", resource.tenantId)
    }

    @Test
    fun parsesEventResource() {
        val resource = parser.parseEvent("https://api.example.com/tenants/tenant-a/events/event-1")
        assertEquals("tenant-a", resource.tenantId)
        assertEquals("event-1", resource.eventId)
    }

    @Test
    fun acceptsMaximumLengthIdsAndPreservesCase() {
        val tenantId = "A".repeat(64)
        val eventId = "Event_123"

        val resource = parser.parseEvent("https://api.example.com/tenants/$tenantId/events/$eventId")

        assertEquals(tenantId, resource.tenantId)
        assertEquals(eventId, resource.eventId)
    }

    @Test
    fun rejectsIdsLongerThanMaximumLength() {
        assertFailsWith<ResourceValidationException> {
            parser.parseTenant("https://api.example.com/tenants/${"a".repeat(65)}")
        }
        assertFailsWith<ResourceValidationException> {
            parser.parseEvent("https://api.example.com/tenants/tenant-a/events/${"e".repeat(65)}")
        }
    }

    @Test
    fun rejectsEmptyUnicodeWhitespaceAndEncodedSlashIds() {
        val rejectedResources = listOf(
            "https://api.example.com/tenants/",
            "https://api.example.com/tenants/tenant-a/events/",
            "https://api.example.com/tenants/tenant-a%20/events/event-1",
            "https://api.example.com/tenants/tenant-a/events/%20event-1",
            "https://api.example.com/tenants/tenant-a/events/event-%E3%81%82",
            "https://api.example.com/tenants/tenant-a%2Fother/events/event-1",
        )

        rejectedResources.forEach { resource ->
            assertFailsWith<ResourceValidationException> {
                parser.parseEvent(resource)
            }
        }
    }

    @Test
    fun rejectsInvalidIdWithoutTrimming() {
        assertFailsWith<ResourceValidationException> {
            parser.parseTenant("https://api.example.com/tenants/%20tenant-a")
        }
    }

    @Test
    fun rejectsHttpScheme() {
        assertFailsWith<ResourceValidationException> {
            parser.parseEvent("http://api.example.com/tenants/tenant-a/events/event-1")
        }
    }

    @Test
    fun rejectsQueryFragmentAndUserInfo() {
        val rejectedResources = listOf(
            "https://api.example.com/tenants/tenant-a?debug=true",
            "https://api.example.com/tenants/tenant-a#fragment",
            "https://user@api.example.com/tenants/tenant-a",
        )

        rejectedResources.forEach { resource ->
            assertFailsWith<ResourceValidationException> {
                parser.parseTenant(resource)
            }
        }
    }

    @Test
    fun rejectsExplicitPortAndEmptyPathSegments() {
        val rejectedResources = listOf(
            "https://api.example.com:443/tenants/tenant-a",
            "https://api.example.com/tenants//tenant-a",
            "https://api.example.com/tenants/tenant-a/events//event-1",
        )

        rejectedResources.forEach { resource ->
            assertFailsWith<ResourceValidationException> {
                parser.parseEvent(resource)
            }
        }
    }
}
