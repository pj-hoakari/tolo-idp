package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditLogRepository
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.aot.DisabledInAotMode
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.postgresql.PostgreSQLContainer
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Runs the device authorization regression suite against PostgreSQL.
 *
 * The default suite uses H2. This subclass exercises the same concurrency, revocation and
 * refresh-token reuse cases against the real database so the per-edge row lock and the
 * PostgreSQL `ON CONFLICT` paths are covered. It is skipped only when Docker is unavailable.
 */
@DisabledInAotMode
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
class DeviceAuthorizationPostgresFlowTests(
    @Autowired mockMvc: MockMvc,
    @Autowired jwtEncoder: JwtEncoder,
    @Autowired jwtDecoder: JwtDecoder,
    @Autowired private val jdbcClient: JdbcClient,
    @Autowired private val dataSource: DataSource,
    @Autowired cacheRepository: RelationMembershipCacheRepository,
    @Autowired auditLogRepository: AuditLogRepository,
) : DeviceAuthorizationFlowTests(
    mockMvc = mockMvc,
    jwtEncoder = jwtEncoder,
    jwtDecoder = jwtDecoder,
    jdbcClient = jdbcClient,
    cacheRepository = cacheRepository,
    auditLogRepository = auditLogRepository,
) {
    @Test
    fun suiteRunsAgainstPostgres() {
        val version = jdbcClient.sql("SELECT version()").query(String::class.java).single()
        assertTrue(version.contains("PostgreSQL"), version)
    }

    @Test
    fun refreshWaitsForThePostgresEdgeDeviceRowLock() {
        val edgeDeviceId = "bbbbbbbbbbbbbbbb"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val refreshToken = json(
            poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString,
        )["refresh_token"].asText()

        val response = assertBlocksOnEdgeLock(edgeDeviceId) {
            refresh(refreshToken).andReturn().response
        }
        assertEquals(200, response.status)
    }

    @Test
    fun revokeWaitsForThePostgresEdgeDeviceRowLock() {
        val edgeDeviceId = "cccccccccccccccc"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)

        val response = assertBlocksOnEdgeLock(edgeDeviceId) {
            revoke("event-1", edgeDeviceId).andReturn().response
        }
        assertEquals(204, response.status)
    }

    @Test
    fun initialExchangeWaitsForThePostgresEdgeDeviceRowLock() {
        val edgeDeviceId = "bcbcbcbcbcbcbcbc"
        val code = startDeviceAuthorization()
        approve(userCodeFor(code), "event-1", edgeDeviceId).andExpect(status().isOk)
        val response = assertBlocksOnEdgeLock(edgeDeviceId) { poll(code).andReturn().response }
        assertEquals(200, response.status)
    }

    private fun assertBlocksOnEdgeLock(
        edgeDeviceId: String,
        request: () -> MockHttpServletResponse,
    ): MockHttpServletResponse {
        val executor = Executors.newSingleThreadExecutor()
        try {
            dataSource.connection.use { lockConnection ->
                lockConnection.autoCommit = false
                lockConnection.prepareStatement(
                    "SELECT edge_device_id FROM idp_device_grant_lock WHERE tenant_id = 'tenant-a' AND event_id = 'event-1' AND edge_device_id = ? FOR UPDATE",
                ).use { statement ->
                    statement.setString(1, edgeDeviceId)
                    statement.executeQuery().use { result ->
                        assertTrue(result.next(), "edge lock row must exist")
                    }
                }
                val lockHolderPid = lockConnection.createStatement().use { statement ->
                    statement.executeQuery("SELECT pg_backend_pid()").use { result ->
                        result.next()
                        result.getInt(1)
                    }
                }
                val future = executor.submit(Callable { request() })
                try {
                    assertTrue(
                        awaitEdgeLockWait(lockHolderPid),
                        "request did not wait for the PostgreSQL edge lock",
                    )
                    assertFalse(future.isDone, "request completed while the edge lock was held")
                } finally {
                    lockConnection.rollback()
                }
                return future.get(30, TimeUnit.SECONDS)
            }
        } finally {
            executor.shutdownNow()
        }
    }

    private fun awaitEdgeLockWait(lockHolderPid: Int): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            val waiting = jdbcClient.sql(
                """
                SELECT COUNT(*)
                FROM pg_locks
                WHERE NOT granted
                  AND ? = ANY(pg_blocking_pids(pid))
                """.trimIndent(),
            )
                .param(lockHolderPid)
                .query(Long::class.java)
                .single()
            if (waiting > 0) {
                return true
            }
            Thread.sleep(50)
        }
        return false
    }

    companion object {
        @Container
        @JvmStatic
        val postgres = PostgreSQLContainer("postgres:17-alpine")
            .withDatabaseName("tolo_idp")
            .withUsername("tolo_idp")
            .withPassword("tolo_idp")

        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url") { postgres.jdbcUrl }
            registry.add("spring.datasource.driver-class-name") { postgres.driverClassName }
            registry.add("spring.datasource.username") { postgres.username }
            registry.add("spring.datasource.password") { postgres.password }
            registry.add("spring.flyway.locations") { "classpath:db/postgresql" }
        }
    }
}
