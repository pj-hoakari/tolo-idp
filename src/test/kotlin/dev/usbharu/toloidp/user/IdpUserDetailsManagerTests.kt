package dev.usbharu.toloidp.user

import org.junit.jupiter.api.Test
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.transaction.annotation.Transactional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertFalse

@SpringBootTest(properties = [
    "tolo-idp.seed.enabled=false",
    "spring.datasource.url=jdbc:h2:mem:user-manager;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
])
@Transactional
class IdpUserDetailsManagerTests(@Autowired private val users: IdpUserDetailsManager) {
    @Test
    fun generatedIdentitySurvivesRenameAndCredentialAndAuthorityUpdates() {
        users.createUser("tenant-a", user("before"))
        val created = users.loadUserByUsername("tenant-a", "before")
        assertEquals(created.id, UUID.fromString(created.id).toString())
        assertNotEquals(created.username, created.id)

        users.renameUser(created.id, "after")
        users.updateUser("tenant-a", User.withUsername("after").password("{noop}updated").roles("ADMIN").disabled(true).build())

        val updated = users.loadUserById(created.id)
        assertEquals("after", updated.username)
        assertEquals(created.id, updated.id)
        assertEquals("{noop}updated", updated.password)
        assertEquals(listOf("ROLE_ADMIN"), updated.authorities.map { it.authority })
        assertFalse(updated.isEnabled)
        assertFailsWith<UsernameNotFoundException> { users.loadUserByUsername("tenant-a", "before") }
    }

    @Test
    fun recreatingUsernameGetsNewIdentityAndDoesNotInheritAuthorities() {
        users.createUser("tenant-a", user("reused"))
        val first = users.loadUserByUsername("tenant-a", "reused")
        users.deleteUser("tenant-a", "reused")
        assertFailsWith<UsernameNotFoundException> { users.loadUserById(first.id) }
        users.createUser("tenant-a", User.withUsername("reused").password("{noop}password").roles("OTHER").build())
        val second = users.loadUserByUsername("tenant-a", "reused")
        assertNotEquals(first.id, second.id)
        assertEquals(listOf("ROLE_OTHER"), second.authorities.map { it.authority })
    }

    @Test
    fun duplicateUsernameAndRenameCollisionAreRejected() {
        users.createUser("tenant-a", user("first"))
        users.createUser("tenant-a", user("second"))
        assertFailsWith<DataIntegrityViolationException> { users.createUser("tenant-a", user("first")) }
        val second = users.loadUserByUsername("tenant-a", "second")
        assertFailsWith<DataIntegrityViolationException> { users.renameUser(second.id, "first") }
        assertEquals(second.id, users.loadUserByUsername("tenant-a", "second").id)
    }

    @Test
    fun passwordChangeUsesStableSessionIdentityAndVerifiesOldPassword() {
        users.createUser("tenant-a", user("password-user"))
        val user = users.loadUserByUsername("tenant-a", "password-user")
        users.renameUser(user.id, "renamed-password-user")
        SecurityContextHolder.getContext().authentication =
            UsernamePasswordAuthenticationToken.authenticated(user.id, null, user.authorities)
        try {
            assertFailsWith<BadCredentialsException> { users.changePassword("wrong", "{noop}changed") }
            assertEquals("{noop}password", users.loadUserById(user.id).password)
            users.changePassword("password", "{noop}changed")
            assertEquals("{noop}changed", users.loadUserById(user.id).password)
        } finally {
            SecurityContextHolder.clearContext()
        }
    }

    @Test
    fun sameUsernameIsIsolatedAcrossTenantsForAllManagementOperations() {
        users.createUser("tenant-a", user("same"))
        users.createUser("tenant-b", User.withUsername("same").password("{noop}other-password").roles("OTHER").build())
        val first = users.loadUserByUsername("tenant-a", "same")
        val second = users.loadUserByUsername("tenant-b", "same")
        assertNotEquals(first.id, second.id)
        assertEquals("tenant-a", first.tenantId)
        assertEquals("tenant-b", second.tenantId)
        assertFailsWith<UsernameNotFoundException> { users.loadUserByUsername("same") }
        assertFailsWith<dev.usbharu.toloidp.relation.RelationLookupException> {
            users.requireTenantUser("tenant-a", second.id)
        }
        assertFalse(users.userExists("tenant-c", "same"))
        users.updateUser("tenant-a", User.withUsername("same").password("{noop}updated").roles("ADMIN").build())
        assertEquals("{noop}other-password", users.loadUserByUsername("tenant-b", "same").password)
        assertEquals(listOf("ROLE_OTHER"), users.loadUserByUsername("tenant-b", "same").authorities.map { it.authority })
        users.deleteUser("tenant-a", "same")
        assertFalse(users.userExists("tenant-a", "same"))
        assertEquals(second.id, users.loadUserByUsername("tenant-b", "same").id)
        users.createUser("tenant-a", user("renamed"))
        val third = users.loadUserByUsername("tenant-a", "renamed")
        users.renameUser(third.id, "same")
        assertEquals(third.id, users.loadUserByUsername("tenant-a", "same").id)
        assertEquals(second.id, users.loadUserByUsername("tenant-b", "same").id)
    }

    private fun user(username: String) = User.withUsername(username).password("{noop}password").roles("USER").build()
}
