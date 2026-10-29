package dev.usbharu.toloidp.user

import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Test
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class UserSurrogateKeyMigrationTests {
    @Test
    fun replacesTenantlessDevelopmentUsersWithTenantScopedSchema() {
        val source = DriverManagerDataSource("jdbc:h2:mem:migration-${UUID.randomUUID()};DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false", "sa", "")
        Flyway.configure().dataSource(source).target("5").load().migrate()
        val jdbc = JdbcTemplate(source)
        jdbc.update("INSERT INTO users VALUES ('legacy', '{noop}password', false)")
        jdbc.update("INSERT INTO authorities VALUES ('legacy', 'ROLE_USER')")
        jdbc.update("INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, authorization_grant_type) VALUES ('old', 'client', 'legacy', 'authorization_code')")
        jdbc.update("INSERT INTO oauth2_authorization_consent VALUES ('client', 'legacy', 'SCOPE_openid')")
        Flyway.configure().dataSource(source).load().migrate()
        for (table in listOf("idp_users", "idp_user_authorities", "oauth2_authorization", "oauth2_authorization_consent")) {
            assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM $table", Int::class.java))
        }
        val users = IdpUserDetailsManager(source, PasswordEncoderFactories.createDelegatingPasswordEncoder())
        val details = User.withUsername("same").password("{noop}password").roles("USER").build()
        users.createUser("tenant-a", details)
        users.createUser("tenant-b", details)
        assertNotEquals(users.loadUserByUsername("tenant-a", "same").id, users.loadUserByUsername("tenant-b", "same").id)
        val id = users.loadUserByUsername("tenant-a", "same").id
        Flyway.configure().dataSource(source).load().migrate()
        assertEquals(id, users.loadUserByUsername("tenant-a", "same").id)
    }
}
