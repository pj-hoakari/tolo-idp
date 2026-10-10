package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.logging.structuredDebug
import dev.usbharu.toloidp.logging.structuredTrace
import dev.usbharu.toloidp.resource.ResourceParser
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Primary
import org.springframework.stereotype.Service
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.TransactionDefinition
import org.springframework.transaction.support.TransactionTemplate
import java.time.Clock
import java.time.Instant

/**
 * remote relation API の前段で短期間の所属キャッシュを使う、主系の [RelationService] 実装。
 *
 * lookup 前に tenant ID を検証し、認可と Token Exchange の判定に使う正規化済みの
 * [TenantMembership] だけをキャッシュする。リモート呼び出しはキャッシュのトランザクションの外で行い、
 * 呼び出し開始より後に確定した purge の結果は書き戻さない。
 */
@Service
@Primary
class CachedRelationService(
    @Qualifier("httpRelationService")
    private val delegate: RelationService,
    private val cacheStore: RelationMembershipCacheStore,
    private val properties: IdpProperties,
    private val resourceParser: ResourceParser,
    private val clock: Clock,
    transactionManager: PlatformTransactionManager,
) : RelationService {
    private val withoutTransaction = TransactionTemplate(transactionManager).apply {
        propagationBehavior = TransactionDefinition.PROPAGATION_NOT_SUPPORTED
    }

    /**
     * ユーザーの tenant / event 所属情報を返す。
     *
     * 有効期限内のキャッシュがあればそれを使い、なければ delegate から取得して更新する。
     */
    override fun getMembership(tenantId: String, userId: String): TenantMembership {
        log.structuredTrace("Relation membership lookup started", "event" to "relation_membership_lookup_started", "tenant_id" to tenantId, "subject" to userId)
        resourceParser.requireValidId(tenantId)
        val now = Instant.now(clock)
        val lookup = cacheStore.lookup(tenantId, userId, now)
        lookup.membership?.let {
            log.structuredDebug(
                "Relation membership cache hit",
                "event" to "relation_membership_cache_lookup",
                "tenant_id" to tenantId,
                "subject" to userId,
                "cache_hit" to true,
                "expires_at" to lookup.expiresAt,
            )
            log.structuredTrace("Relation membership lookup completed", "event" to "relation_membership_lookup_completed", "tenant_id" to tenantId, "subject" to userId, "cache_hit" to true)
            return it
        }

        log.structuredDebug(
            "Relation membership cache miss",
            "event" to "relation_membership_cache_lookup",
            "tenant_id" to tenantId,
            "subject" to userId,
            "cache_hit" to false,
        )
        val observedGeneration = lookup.generation!!
        val membership = withoutTransaction.execute<TenantMembership> {
            delegate.getMembership(tenantId, userId)
        }!!
        val cacheId = RelationMembershipCacheId(tenantId, userId)
        val expiresAt = now.plus(properties.relation.cache.ttl)
        val saved = cacheStore.saveIfUnchanged(
            observedGeneration,
            RelationMembershipCache(
                cacheId = cacheId,
                membership = membership,
                cachedAt = now,
                expiresAt = expiresAt,
            ),
        )
        if (saved) {
            log.structuredDebug(
                "Relation membership cached",
                "event" to "relation_membership_cached",
                "tenant_id" to tenantId,
                "subject" to userId,
                "event_count" to membership.events.size,
                "expires_at" to expiresAt,
            )
        } else {
            log.structuredDebug(
                "Relation membership cache write skipped",
                "event" to "relation_membership_cache_write_skipped",
                "tenant_id" to tenantId,
                "subject" to userId,
                "failure_reason" to "purged",
            )
        }
        log.structuredTrace("Relation membership lookup completed", "event" to "relation_membership_lookup_completed", "tenant_id" to tenantId, "subject" to userId, "cache_hit" to false)
        return membership
    }

    companion object {
        private val log = LoggerFactory.getLogger(CachedRelationService::class.java)
    }
}
