package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.RelationRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.BeforeEach
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.transaction.PlatformTransactionManager
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertTrue

@SpringBootTest(properties = ["tolo-idp.seed.enabled=false"])
class CachedRelationServiceTests(
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val cacheStore: RelationMembershipCacheStore,
    @Autowired private val cacheController: RelationCacheController,
    @Autowired private val transactionManager: PlatformTransactionManager,
    @Autowired private val resourceParser: ResourceParser,
) {
    private val now = Instant.parse("2026-06-01T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val properties = IdpProperties(
        relation = IdpProperties.Relation(
            cache = IdpProperties.Relation.Cache(ttl = Duration.ofMinutes(5)),
        ),
    )

    @BeforeEach
    fun clearCache() {
        cacheRepository.deleteAll()
    }

    @Test
    fun firstLookupDelegatesAndWritesCacheRow() {
        val delegate = RecordingRelationService()
        val service = service(delegate)

        val membership = service.getMembership("tenant-a", "user-123")

        assertEquals(sampleMembership("tenant-a"), membership)
        assertEquals(listOf("tenant-a" to "user-123"), delegate.calls)
        assertEquals(1, cacheRowCount())
    }

    @Test
    fun secondLookupWithinTtlUsesCacheWithoutDelegateCall() {
        val delegate = RecordingRelationService()
        val service = service(delegate)

        service.getMembership("tenant-a", "user-123")
        service.getMembership("tenant-a", "user-123")

        assertEquals(listOf("tenant-a" to "user-123"), delegate.calls)
        assertEquals(1, cacheRowCount())
    }

    @Test
    fun expiredRowIsIgnoredAndRefreshed() {
        cacheMembership("tenant-a", "user-123", sampleMembership("tenant-a", "event-old"), now.minusSeconds(600), now.minusSeconds(1))
        val delegate = RecordingRelationService()
        val service = service(delegate)

        val membership = service.getMembership("tenant-a", "user-123")

        assertEquals(sampleMembership("tenant-a"), membership)
        assertEquals(listOf("tenant-a" to "user-123"), delegate.calls)
        assertEquals(sampleMembership("tenant-a"), cachedMembership("tenant-a", "user-123"))
    }

    @Test
    fun delegateFailuresAreNotCached() {
        val delegate = RecordingRelationService(failure = RelationLookupException("relation_lookup_failed"))
        val service = service(delegate)

        assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }

        assertEquals(0, cacheRowCount())
        assertNull(cachedMembership("tenant-a", "user-123"))
    }

    @Test
    fun purgeAllAndPurgeOneRemoveExpectedRows() {
        cacheMembership("tenant-a", "user-1", sampleMembership("tenant-a"), now, now.plusSeconds(300))
        cacheMembership("tenant-a", "user-2", sampleMembership("tenant-a"), now, now.plusSeconds(300))
        cacheMembership("tenant-b", "user-1", sampleMembership("tenant-b"), now, now.plusSeconds(300))

        cacheRepository.deleteById(RelationMembershipCacheId("tenant-a", "user-1"))

        assertNull(cachedMembership("tenant-a", "user-1"))
        assertEquals(sampleMembership("tenant-a"), cachedMembership("tenant-a", "user-2"))
        assertEquals(sampleMembership("tenant-b"), cachedMembership("tenant-b", "user-1"))

        cacheRepository.deleteAll()

        assertEquals(0, cacheRowCount())
    }

    @Test
    fun purgeAllDuringMissDoesNotWriteBackFetchedMembership() {
        assertPurgeDuringMissDoesNotWriteBack {
            cacheController.purgeAll()
        }
    }

    @Test
    fun purgeOneDuringMissDoesNotWriteBackFetchedMembership() {
        assertPurgeDuringMissDoesNotWriteBack {
            cacheController.purgeOne("tenant-a", "user-1")
        }
    }

    private fun assertPurgeDuringMissDoesNotWriteBack(purge: () -> Unit) {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val delegate = BlockingRelationService(entered, release)
        val service = service(delegate)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit<TenantMembership> {
                service.getMembership("tenant-a", "user-1")
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            purge()
            assertEquals(0, cacheRowCount())
            release.countDown()
            assertEquals(sampleMembership("tenant-a"), future.get(5, TimeUnit.SECONDS))
            assertNull(cachedMembership("tenant-a", "user-1"))
            assertEquals(0, cacheRowCount())
        } finally {
            release.countDown()
            executor.shutdownNow()
        }
    }

    private fun service(delegate: RelationService): CachedRelationService =
        CachedRelationService(delegate, cacheStore, properties, resourceParser, clock, transactionManager)

    private fun cacheRowCount(): Int =
        cacheRepository.count().toInt()

    private fun cacheMembership(
        tenantId: String,
        userId: String,
        membership: TenantMembership,
        cachedAt: Instant,
        expiresAt: Instant,
    ) {
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId(tenantId, userId),
                membership = membership,
                cachedAt = cachedAt,
                expiresAt = expiresAt,
            ),
        )
    }

    private fun cachedMembership(tenantId: String, userId: String): TenantMembership? =
        cacheRepository.findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(tenantId, userId, now)
            ?.membership

    private fun sampleMembership(tenantId: String, eventId: String = "event-1"): TenantMembership =
        TenantMembership(
            tenantId = tenantId,
            tenantRole = RelationRole.OWNER,
            events = listOf(EventMembership(eventId, RelationRole.STAFF)),
        )

    private inner class BlockingRelationService(
        private val entered: CountDownLatch,
        private val release: CountDownLatch,
    ) : RelationService {
        override fun getMembership(tenantId: String, userId: String): TenantMembership {
            entered.countDown()
            assertTrue(release.await(10, TimeUnit.SECONDS))
            return sampleMembership(tenantId)
        }
    }

    private inner class RecordingRelationService(
        private val failure: RuntimeException? = null,
    ) : RelationService {
        val calls = mutableListOf<Pair<String, String>>()

        override fun getMembership(tenantId: String, userId: String): TenantMembership {
            calls += tenantId to userId
            failure?.let { throw it }
            return sampleMembership(tenantId)
        }
    }
}
