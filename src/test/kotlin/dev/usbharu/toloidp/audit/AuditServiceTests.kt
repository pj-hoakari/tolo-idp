package dev.usbharu.toloidp.audit

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@SpringBootTest(properties = ["tolo-idp.seed.enabled=false"])
class AuditServiceTests(
    @Autowired private val repository: AuditLogRepository,
    @Autowired private val objectMapper: tools.jackson.databind.ObjectMapper,
) {
    private val clock = Clock.fixed(Instant.parse("2026-06-01T00:00:00Z"), ZoneOffset.UTC)
    private val service by lazy { AuditService(repository, objectMapper, clock) }

    @BeforeEach
    fun setUp() {
        repository.deleteAll()
    }

    @Test
    fun recordsAuditEventAsColumnsAndJsonPayload() {
        service.record(
            TokenAuditEvent(
                requestId = "request-1",
                clientId = "client-123",
                subject = "user-123",
                sourceTokenUse = "tenant_access",
                requestedTokenUse = "event_access",
                requestedAudience = "backend-api",
                requestedResource = "https://api.example.com/tenants/tenant-a/events/event-1",
                requestedScope = listOf("events.read", "events.manage"),
                issuedScope = listOf("events.read"),
                tenantId = "tenant-a",
                eventId = "event-1",
                result = "success",
                failureReason = null,
                sourceIp = "127.0.0.1",
                userAgent = "test-agent",
                issuedJti = "jti-1",
            ),
        )

        val row = repository.findAll().single()

        assertEquals("request-1", row.requestId)
        assertEquals("client-123", row.clientId)
        assertEquals("user-123", row.subject)
        assertEquals("tenant_access", row.sourceTokenUse)
        assertEquals("event_access", row.requestedTokenUse)
        assertEquals("backend-api", row.requestedAudience)
        assertEquals("events.read events.manage", row.requestedScope)
        assertEquals("events.read", row.issuedScope)
        assertEquals("tenant-a", row.tenantId)
        assertEquals("event-1", row.eventId)
        assertEquals("success", row.result)
        assertEquals(null, row.failureReason)
        assertEquals("127.0.0.1", row.sourceIp)
        assertEquals("test-agent", row.userAgent)
        assertEquals("jti-1", row.issuedJti)
        assertContains(row.payload, """"timestamp":"2026-06-01T00:00:00Z"""")
        assertContains(row.payload, """"requestedScope":["events.read","events.manage"]""")
    }

    @Test
    fun boundsLongRequestFieldsAndRecordsPayloadDigest() {
        val audience = "a".repeat(300)
        val resource = "https://api.example.com/tenants/tenant-a/events/" + "e".repeat(1200)
        val scopes = (1..1000).map { "scope-$it" }

        service.record(
            TokenAuditEvent(
                clientId = "client-123",
                requestedTokenUse = "event_access",
                requestedAudience = audience,
                requestedResource = resource,
                requestedScope = scopes,
                issuedScope = scopes,
                result = "failure",
                failureReason = "audience_not_allowed",
            ),
        )

        val row = repository.findAll().single()
        assertEquals(200, row.requestedAudience?.length)
        assertTrue(row.requestedAudience.orEmpty().endsWith("...[truncated]"))
        assertEquals(1000, row.requestedResource?.length)
        assertTrue(row.requestedResource.orEmpty().endsWith("...[truncated]"))
        assertEquals(1000, row.requestedScope.length)
        assertTrue(row.requestedScope.endsWith("...[truncated]"))
        assertEquals(1000, row.issuedScope.length)
        assertTrue(row.issuedScope.endsWith("...[truncated]"))
        assertContains(row.payload, """"payloadTruncated":true""")
        assertContains(row.payload, """"payloadSha256":""")
        assertContains(row.payload, """"payloadLength":""")
        assertFalse(row.payload.contains(audience))
        assertFalse(row.payload.contains(resource))
    }

    @Test
    fun preservesValuesAtTheColumnLimit() {
        val audience = "a".repeat(200)
        val resource = "r".repeat(1000)
        val requestedScope = "s".repeat(1000)
        val issuedScope = "i".repeat(1000)

        service.record(
            TokenAuditEvent(
                clientId = "client-123",
                requestedTokenUse = "event_access",
                requestedAudience = audience,
                requestedResource = resource,
                requestedScope = listOf(requestedScope),
                issuedScope = listOf(issuedScope),
                result = "failure",
                failureReason = "audience_not_allowed",
            ),
        )

        val row = repository.findAll().single()
        assertEquals(audience, row.requestedAudience)
        assertEquals(resource, row.requestedResource)
        assertEquals(requestedScope, row.requestedScope)
        assertEquals(issuedScope, row.issuedScope)
        assertContains(row.payload, audience)
        assertContains(row.payload, resource)
    }

    @Test
    fun doesNotSplitSurrogatePairsAtTheTruncationBoundary() {
        val audience = "a".repeat(185) + "\uD83D\uDE00" + "b".repeat(20)

        service.record(
            TokenAuditEvent(
                clientId = "client-123",
                requestedTokenUse = "event_access",
                requestedAudience = audience,
                result = "failure",
                failureReason = "audience_not_allowed",
            ),
        )

        val stored = repository.findAll().single().requestedAudience.orEmpty()
        assertTrue(stored.length <= 200)
        assertTrue(stored.endsWith("...[truncated]"))
        assertFalse(stored.last().isHighSurrogate())
    }
}
