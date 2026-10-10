package dev.usbharu.toloidp.relation

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

/**
 * 所属キャッシュの読み書きと purge を、リモート呼び出しより短いトランザクションに分ける。
 *
 * 照会開始時の世代と書き込み時の世代が違えば、そのあいだに purge が確定したとみなして保存しない。
 */
@Service
class RelationMembershipCacheStore(
    private val cacheRepository: RelationMembershipCacheRepository,
    private val generationRepository: RelationCacheGenerationRepository,
) {
    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    fun lookup(tenantId: String, userId: String, now: Instant): Lookup {
        val cached = cacheRepository
            .findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(tenantId, userId, now)
        if (cached != null) {
            return Lookup(membership = cached.membership, expiresAt = cached.expiresAt, generation = null)
        }
        return Lookup(membership = null, expiresAt = null, generation = generationRepository.currentGeneration())
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    fun saveIfUnchanged(observedGeneration: Long, cache: RelationMembershipCache): Boolean {
        val currentGeneration = generationRepository.lockGeneration()
        if (currentGeneration != observedGeneration) {
            return false
        }
        cacheRepository.deleteById(cache.cacheId)
        cacheRepository.save(cache)
        return true
    }

    @Transactional
    fun purgeAll() {
        generationRepository.bumpGeneration()
        cacheRepository.deleteAll()
    }

    @Transactional
    fun purgeOne(tenantId: String, userId: String) {
        generationRepository.bumpGeneration()
        cacheRepository.deleteById(RelationMembershipCacheId(tenantId, userId))
    }

    data class Lookup(
        val membership: TenantMembership?,
        val expiresAt: Instant?,
        val generation: Long?,
    )
}
