package dev.usbharu.toloidp.relation

import com.zaxxer.hikari.HikariDataSource
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

@SpringBootTest
class RelationLookupTimeoutTests(
    @Autowired private val relationService: RelationService,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val dataSource: DataSource,
) {
    @BeforeEach
    fun clearCache() {
        cacheRepository.deleteAll()
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun readTimeoutFailsWithoutHoldingJdbcConnection() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit<TenantMembership> {
                relationService.getMembership("tenant-a", "user-1")
            }
            assertTrue(accepted.await(5, TimeUnit.SECONDS))
            val acceptedAt = Instant.now()
            val idleDeadline = acceptedAt.plusMillis(500)
            var activeConnections = activeConnections()
            while (activeConnections != 0 && Instant.now().isBefore(idleDeadline) && !future.isDone) {
                Thread.sleep(20)
                activeConnections = activeConnections()
            }
            assertFalse(future.isDone, "lookup finished before the read wait could be observed")
            assertEquals(0, activeConnections)
            try {
                future.get(3, TimeUnit.SECONDS)
                fail("expected relation lookup to fail")
            } catch (ex: ExecutionException) {
                val lookup = ex.cause
                assertTrue(lookup is RelationLookupException)
                assertEquals("relation_lookup_failed", (lookup as RelationLookupException).reason)
            }
            assertTrue(Duration.between(acceptedAt, Instant.now()) < Duration.ofMillis(2500))
        } finally {
            executor.shutdownNow()
        }
    }

    private fun activeConnections(): Int =
        dataSource.unwrap(HikariDataSource::class.java).hikariPoolMXBean.activeConnections

    companion object {
        private val accepted = CountDownLatch(1)
        private val serverSocket = ServerSocket()
        private val acceptThread: Thread

        init {
            serverSocket.bind(InetSocketAddress("127.0.0.1", 0), 1)
            acceptThread = Thread {
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
        }

        @DynamicPropertySource
        @JvmStatic
        fun relationProperties(registry: DynamicPropertyRegistry) {
            registry.add("tolo-idp.relation.base-url") { "http://127.0.0.1:${serverSocket.localPort}" }
            registry.add("tolo-idp.relation.read-timeout") { "1s" }
            registry.add("tolo-idp.relation.connect-timeout") { "1s" }
            registry.add("tolo-idp.seed.enabled") { "false" }
        }

        @AfterAll
        @JvmStatic
        fun closeServer() {
            serverSocket.close()
            acceptThread.join(1_000)
        }
    }
}
