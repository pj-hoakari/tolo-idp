package dev.usbharu.toloidp.user

import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class UserSurrogateKeyMigrationTests {
    @Test
    fun migratesExistingUsersAndAuthoritiesAndInvalidatesUsernameAuthorizations() {
        val dataSource = DriverManagerDataSource("jdbc:h2:mem:migration-${UUID.randomUUID()};DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false", "sa", "")
        Flyway.configure().dataSource(dataSource).target("5").load().migrate()
        val jdbc = JdbcTemplate(dataSource)
        jdbc.update("INSERT INTO users VALUES ('legacy', '{noop}password', false)")
        jdbc.update("INSERT INTO users VALUES ('another', '{noop}another', true)")
        jdbc.update("INSERT INTO authorities VALUES ('legacy', 'ROLE_USER')")
        jdbc.update("INSERT INTO authorities VALUES ('legacy', 'ROLE_ADMIN')")
        jdbc.update("INSERT INTO authorities VALUES ('another', 'ROLE_USER')")
        jdbc.update("INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, authorization_grant_type) VALUES ('old', 'client', 'legacy', 'authorization_code')")
        jdbc.update("INSERT INTO oauth2_authorization_consent VALUES ('client', 'legacy', 'SCOPE_openid')")
        jdbc.update("INSERT INTO idp_relation_membership_cache VALUES ('tenant-a', 'legacy', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")

        Flyway.configure().dataSource(dataSource).load().migrate()

        val users = IdpUserDetailsManager(dataSource)
        val legacy = users.loadUserByUsername("legacy")
        assertEquals(legacy.userId, UUID.fromString(legacy.userId).toString())
        assertNotEquals(legacy.userId, users.loadUserByUsername("another").userId)
        assertEquals("{noop}password", legacy.password)
        assertFalse(legacy.isEnabled)
        assertEquals(setOf("ROLE_USER", "ROLE_ADMIN"), legacy.authorities.map { it.authority }.toSet())
        for (table in listOf("oauth2_authorization", "oauth2_authorization_consent", "idp_relation_membership_cache")) {
            assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM $table", Int::class.java))
        }
        // A second migration must not generate new identities.
        Flyway.configure().dataSource(dataSource).load().migrate()
        assertEquals(legacy.userId, users.loadUserByUsername("legacy").userId)
    }
}
