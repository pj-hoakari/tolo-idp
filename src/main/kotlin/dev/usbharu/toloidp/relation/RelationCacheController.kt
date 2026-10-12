package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.resource.ResourceValidationException
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException

@RestController
@RequestMapping("/internal/relation-cache")
class RelationCacheController(
    private val cacheRepository: RelationMembershipCacheRepository,
    private val cacheStore: RelationMembershipCacheStore,
    private val resourceParser: ResourceParser,
) {
    @DeleteMapping
    @Transactional
    fun purgeAll(): ResponseEntity<Void> {
        val cacheCount = cacheRepository.count()
        log.structuredInfo(
            "Relation membership cache purge started",
            "event" to "relation_membership_cache_purge_started",
            "target" to "all",
            "cache_count" to cacheCount,
        )
        cacheStore.purgeAll()
        log.structuredInfo(
            "Relation membership cache purge completed",
            "event" to "relation_membership_cache_purge_completed",
            "target" to "all",
            "purged_count" to cacheCount,
            "result" to "success",
        )
        return ResponseEntity.noContent().build()
    }

    @DeleteMapping("/tenants/{tenantId}/users/{userId}")
    @Transactional
    fun purgeOne(
        @PathVariable tenantId: String,
        @PathVariable userId: String,
    ): ResponseEntity<Void> {
        try {
            resourceParser.requireValidId(tenantId)
        } catch (ex: ResourceValidationException) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, null, ex)
        }
        log.structuredInfo(
            "Relation membership cache purge started",
            "event" to "relation_membership_cache_purge_started",
            "tenant_id" to tenantId,
            "subject" to userId,
        )
        cacheStore.purgeOne(tenantId, userId)
        log.structuredInfo(
            "Relation membership cache purge completed",
            "event" to "relation_membership_cache_purge_completed",
            "tenant_id" to tenantId,
            "subject" to userId,
            "result" to "success",
        )
        return ResponseEntity.noContent().build()
    }

    companion object {
        private val log = LoggerFactory.getLogger(RelationCacheController::class.java)
    }
}
