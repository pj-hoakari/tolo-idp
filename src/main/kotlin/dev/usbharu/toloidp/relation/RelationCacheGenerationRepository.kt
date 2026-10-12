package dev.usbharu.toloidp.relation

import org.springframework.data.annotation.Id
import org.springframework.data.jdbc.repository.query.Modifying
import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.Repository
import org.springframework.transaction.annotation.Transactional

@Table("idp_relation_cache_generation")
class RelationCacheGeneration(
    @Id
    val id: Int,
    @Column("cache_generation")
    val cacheGeneration: Long,
)

interface RelationCacheGenerationRepository : Repository<RelationCacheGeneration, Int> {
    @Transactional(readOnly = true)
    @Query(
        """
        SELECT cache_generation
        FROM idp_relation_cache_generation
        WHERE id = 1
        """,
    )
    fun currentGeneration(): Long

    @Transactional
    @Query(
        """
        SELECT cache_generation
        FROM idp_relation_cache_generation
        WHERE id = 1
        FOR UPDATE
        """,
    )
    fun lockGeneration(): Long

    @Transactional
    @Modifying
    @Query(
        """
        UPDATE idp_relation_cache_generation
        SET cache_generation = cache_generation + 1
        WHERE id = 1
        """,
    )
    fun bumpGeneration()
}
