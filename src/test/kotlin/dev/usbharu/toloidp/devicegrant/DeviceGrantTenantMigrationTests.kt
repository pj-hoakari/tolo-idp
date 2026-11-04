package dev.usbharu.toloidp.devicegrant

import org.flywaydb.core.Flyway
import org.flywaydb.core.api.FlywayException
import org.junit.jupiter.api.Test
import org.springframework.dao.DuplicateKeyException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DeviceGrantTenantMigrationTests {
    @Test
    fun legacyRevocationsArePreservedForEveryPreviouslyAffectedTenant() {
        val source = databaseAtV8()
        val jdbc = JdbcTemplate(source)
        for (tenant in listOf("tenant-a", "tenant-b")) {
            jdbc.update(
                """
                INSERT INTO idp_device_grant
                    (id, tenant_id, event_id, edge_device_id, approver_sub, client_id,
                     approved_at, absolute_expires_at, created_at)
                VALUES (?, ?, 'event-1', '0123456789abcdef', 'staff', 'esp-camera',
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """.trimIndent(), tenant, tenant,
            )
        }
        jdbc.update("INSERT INTO idp_revoked_edge_device VALUES ('event-1', '0123456789abcdef', CURRENT_TIMESTAMP, TRUE)")
        Flyway.configure().dataSource(source).load().migrate()
        assertEquals(listOf("tenant-a", "tenant-b"), jdbc.queryForList(
            "SELECT tenant_id FROM idp_revoked_edge_device WHERE permanent = TRUE ORDER BY tenant_id", String::class.java,
        ))
        // Tenant-specific keys allow identical event/edge identifiers without collisions.
        for (tenant in listOf("tenant-a", "tenant-b")) {
            jdbc.update("INSERT INTO idp_device_grant_lock VALUES (?, 'event-1', '0123456789abcdef')", tenant)
        }
        assertFailsWith<DuplicateKeyException> {
            jdbc.update("INSERT INTO idp_device_grant_lock VALUES ('tenant-a', 'event-1', '0123456789abcdef')")
        }
        assertFailsWith<DuplicateKeyException> {
            jdbc.update("INSERT INTO idp_revoked_edge_device VALUES ('tenant-a', 'event-1', '0123456789abcdef', CURRENT_TIMESTAMP, FALSE)")
        }
    }

    @Test
    fun unmappableRevocationStopsMigrationWithoutDiscardingTheMarker() {
        val source = databaseAtV8()
        val jdbc = JdbcTemplate(source)
        jdbc.update("INSERT INTO idp_revoked_edge_device VALUES ('event-1', '0123456789abcdef', CURRENT_TIMESTAMP, TRUE)")
        assertFailsWith<FlywayException> { Flyway.configure().dataSource(source).load().migrate() }
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM idp_revoked_edge_device WHERE permanent = TRUE", Int::class.java))
    }

    private fun databaseAtV8(): DriverManagerDataSource {
        val source = DriverManagerDataSource(
            "jdbc:h2:mem:device-migration-${UUID.randomUUID()};DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false", "sa", "",
        )
        Flyway.configure().dataSource(source).target("8").load().migrate()
        return source
    }
}
