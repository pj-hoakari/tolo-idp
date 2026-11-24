package dev.usbharu.toloidp.relation

import ch.qos.logback.classic.Level
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.test.system.CapturedOutput
import org.springframework.boot.test.system.OutputCaptureExtension
import tools.jackson.databind.json.JsonMapper
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@ExtendWith(OutputCaptureExtension::class)
class HttpRelationServiceTests {
    private lateinit var server: HttpServer
    private lateinit var service: HttpRelationService
    private val parser = ResourceParser(IdpProperties())

    @BeforeEach
    fun setUp() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.start()
        service = HttpRelationService(
            IdpProperties(
                relation = IdpProperties.Relation(
                    baseUrl = "http://127.0.0.1:${server.address.port}",
                    connectTimeout = Duration.ofSeconds(1),
                ),
            ),
            parser,
        )
    }

    @AfterEach
    fun tearDown() {
        server.stop(0)
    }

    @Test
    fun returnsTenantMembershipFromRelationResponse() {
        respondWith(
            status = 200,
            body = """
                {
                  "memberships": [
                    {
                      "user_id": "user-123",
                      "tenant_id": "tenant-a",
                      "tenant_role": "owner",
                      "event_roles": [{"event_id": "event-1", "role": "staff"}, {"event_id": "event-2", "role": "owner"}]
                    }
                  ]
                }
            """.trimIndent(),
        )

        val membership = service.getMembership("tenant-a", "user-123")

        assertEquals("tenant-a", membership.tenantId)
        assertEquals(RelationRole.OWNER, membership.tenantRole)
        assertEquals(
            listOf(
                EventMembership("event-1", RelationRole.STAFF),
                EventMembership("event-2", RelationRole.OWNER),
            ),
            membership.events,
        )
    }

    @Test
    fun convertsNotFoundToTenantNotFound() {
        respondWith(404, """{"error":"missing"}""")

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("tenant_not_found", exception.reason)
    }

    @Test
    fun rejectsMismatchedTenant() {
        respondWith(
            200,
            """
            {
              "memberships": [
                {
                  "user_id": "user-123",
                  "tenant_id": "tenant-b",
                  "tenant_role": "owner",
                  "event_roles": []
                }
              ]
            }
            """.trimIndent(),
        )

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_response_invalid", exception.reason)
    }

    @Test
    fun rejectsMismatchedUser() {
        respondWith(200, """{"memberships": [{"user_id": "user-456", "tenant_id": "tenant-a", "tenant_role": "owner", "event_roles": []}]}""")

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_response_invalid", exception.reason)
    }

    @Test
    fun rejectsMultipleMemberships() {
        val membership = """{"user_id": "user-123", "tenant_id": "tenant-a", "tenant_role": "owner", "event_roles": []}"""
        respondWith(200, """{"memberships": [$membership, $membership]}""")

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_response_invalid", exception.reason)
    }

    @Test
    fun treatsEmptyMembershipsAsNotTenantMember() {
        respondWith(200, """{"memberships": []}""")

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("user_not_tenant_member", exception.reason)
    }

    @Test
    fun rejectsUnknownRole() {
        respondWith(
            200,
            """
            {
              "memberships": [
                {
                  "user_id": "user-123",
                  "tenant_id": "tenant-a",
                  "tenant_role": "admin",
                  "event_roles": []
                }
              ]
            }
            """.trimIndent(),
        )

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_role_unknown", exception.reason)
    }

    @Test
    fun rejectsInvalidEventId() {
        respondWith(
            200,
            """
            {
              "memberships": [
                {
                  "user_id": "user-123",
                  "tenant_id": "tenant-a",
                  "tenant_role": "owner",
                  "event_roles": [{"event_id": " event-1", "role": "staff"}]
                }
              ]
            }
            """.trimIndent(),
        )

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_response_invalid", exception.reason)
    }

    @Test
    fun convertsMalformedJsonToInvalidResponse() {
        respondWith(200, "{not-json")

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_lookup_failed", exception.reason)
    }

    @Test
    fun validatesTenantIdBeforeCallingRelationService() {
        val exception = assertFailsWith<RuntimeException> {
            service.getMembership(" tenant-a", "user-123")
        }
        assertEquals("resource_invalid_format", exception.message)
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    fun readTimeoutFailsWhenPeerSendsNoBytes() {
        ServerSocket().use { serverSocket ->
            serverSocket.bind(InetSocketAddress("127.0.0.1", 0), 1)
            val accepted = CountDownLatch(1)
            val acceptThread = Thread {
                try {
                    serverSocket.accept().use { socket ->
                        accepted.countDown()
                        try {
                            socket.getInputStream().read()
                        } catch (_: IOException) {
                        }
                    }
                } catch (_: IOException) {
                }
            }
            acceptThread.isDaemon = true
            acceptThread.start()
            val slowService = HttpRelationService(
                IdpProperties(
                    relation = IdpProperties.Relation(
                        baseUrl = "http://127.0.0.1:${serverSocket.localPort}",
                        connectTimeout = Duration.ofSeconds(1),
                        readTimeout = Duration.ofSeconds(1),
                    ),
                ),
                parser,
            )
            val started = Instant.now()
            try {
                val exception = assertFailsWith<RelationLookupException> {
                    slowService.getMembership("tenant-a", "user-1")
                }
                assertEquals("relation_lookup_failed", exception.reason)
                assertTrue(accepted.count == 0L)
                assertTrue(Duration.between(started, Instant.now()) < Duration.ofMillis(2500))
            } finally {
                serverSocket.close()
                acceptThread.join(1_000)
            }
        }
    }

    @Test
    fun verifiesARegistrationGrantWithTheTokenOnlyInTheRequestBody(output: CapturedOutput) {
        val requests = mutableListOf<RecordedRequest>()
        answerGrantVerification(200, "application/json", """{"valid":true}""", requests)

        val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as ch.qos.logback.classic.Logger
        val level = root.level
        root.level = Level.TRACE
        val verdict = try {
            service.verify("tenant-a", RegistrationGrant(RegistrationGrantType.INVITATION, GRANT_TOKEN))
        } finally {
            root.level = level
        }

        assertEquals(RegistrationGrantVerdict.VALID, verdict)
        val request = requests.single()
        assertEquals("POST", request.method)
        assertEquals("/tenants/tenant-a/registration-grants/verify", request.path)
        assertNull(request.query)
        assertTrue(request.contentType.orEmpty().startsWith("application/json"))
        assertEquals(mapOf("invitation_token" to GRANT_TOKEN), JsonMapper().readValue(request.body, Map::class.java))
        assertFalse(output.all.contains(GRANT_TOKEN))
    }

    @Test
    fun reportsAnInvalidOwnershipClaimToken() {
        val requests = mutableListOf<RecordedRequest>()
        answerGrantVerification(200, "application/json", """{"valid":false}""", requests)

        val verdict = service.verify("tenant-a", RegistrationGrant(RegistrationGrantType.OWNERSHIP_CLAIM, GRANT_TOKEN))

        assertEquals(RegistrationGrantVerdict.INVALID, verdict)
        assertEquals(mapOf("ownership_claim_token" to GRANT_TOKEN), JsonMapper().readValue(requests.single().body, Map::class.java))
    }

    @ParameterizedTest
    @MethodSource("responsesWithoutAVerdict")
    fun treatsAnythingButAnOkWithABooleanValidAsUnavailable(status: Int, contentType: String, body: String, output: CapturedOutput) {
        answerGrantVerification(status, contentType, body, mutableListOf())

        val verdict = service.verify("tenant-a", RegistrationGrant(RegistrationGrantType.INVITATION, GRANT_TOKEN))

        assertEquals(RegistrationGrantVerdict.UNAVAILABLE, verdict)
        assertFalse(output.all.contains(GRANT_TOKEN))
    }

    @Test
    fun treatsAnUnreachableRelationServiceAsUnavailable(output: CapturedOutput) {
        val closedPort = ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress()).use { it.localPort }
        val unreachable = HttpRelationService(
            IdpProperties(
                relation = IdpProperties.Relation(
                    baseUrl = "http://127.0.0.1:$closedPort",
                    connectTimeout = Duration.ofSeconds(1),
                ),
            ),
            parser,
        )

        val verdict = unreachable.verify("tenant-a", RegistrationGrant(RegistrationGrantType.INVITATION, GRANT_TOKEN))

        assertEquals(RegistrationGrantVerdict.UNAVAILABLE, verdict)
        assertFalse(output.all.contains(GRANT_TOKEN))
    }

    private fun answerGrantVerification(status: Int, contentType: String, body: String, requests: MutableList<RecordedRequest>) {
        server.createContext("/") { exchange ->
            requests += RecordedRequest(
                exchange.requestMethod,
                exchange.requestURI.rawPath,
                exchange.requestURI.rawQuery,
                exchange.requestHeaders.getFirst("Content-Type"),
                exchange.requestBody.readAllBytes().decodeToString(),
            )
            val bytes = body.toByteArray()
            exchange.responseHeaders.add("Content-Type", contentType)
            if (status in 300..399) exchange.responseHeaders.add("Location", "/elsewhere")
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
    }

    private data class RecordedRequest(
        val method: String,
        val path: String,
        val query: String?,
        val contentType: String?,
        val body: String,
    )

    private fun respondWith(status: Int, body: String) {
        server.createContext("/") { exchange ->
            if (exchange.requestURI.rawPath == "/tenants/tenant-a/users/user-123/memberships") {
                exchange.sendJson(status, body)
            } else {
                exchange.sendJson(404, """{"error":"unexpected path"}""")
            }
        }
    }

    private fun HttpExchange.sendJson(status: Int, body: String) {
        val bytes = body.toByteArray()
        responseHeaders.add("Content-Type", "application/json")
        sendResponseHeaders(status, bytes.size.toLong())
        responseBody.use { it.write(bytes) }
    }

    companion object {
        private const val GRANT_TOKEN = "grant-token-value-7f3a"

        @JvmStatic
        fun responsesWithoutAVerdict(): List<Arguments> = listOf(
            Arguments.of(200, "application/json", "{}"),
            Arguments.of(200, "application/json", """{"valid":null}"""),
            Arguments.of(200, "application/json", """{"valid":"true"}"""),
            Arguments.of(200, "application/json", """[{"valid":true}]"""),
            Arguments.of(200, "application/json", "not json"),
            Arguments.of(200, "text/plain", "valid"),
            Arguments.of(201, "application/json", """{"valid":true}"""),
            Arguments.of(302, "application/json", """{"valid":true}"""),
            Arguments.of(400, "application/json", """{"error":"invalid body"}"""),
            Arguments.of(404, "application/json", """{"valid":false}"""),
            Arguments.of(500, "application/json", """{"valid":true}"""),
            Arguments.of(503, "text/plain", "unavailable"),
        )
    }
}
