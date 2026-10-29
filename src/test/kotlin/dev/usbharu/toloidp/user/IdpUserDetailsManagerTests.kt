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
        users.createUser(user("before"))
        val created = users.loadUserByUsername("before")
        assertEquals(created.userId, UUID.fromString(created.userId).toString())
        assertNotEquals(created.username, created.userId)

        users.renameUser(created.userId, "after")
        users.updateUser(User.withUsername("after").password("{noop}updated").roles("ADMIN").disabled(true).build())

        val updated = users.loadUserById(created.userId)
        assertEquals("after", updated.username)
        assertEquals(created.userId, updated.userId)
        assertEquals("{noop}updated", updated.password)
        assertEquals(listOf("ROLE_ADMIN"), updated.authorities.map { it.authority })
        assertFalse(updated.isEnabled)
        assertFailsWith<UsernameNotFoundException> { users.loadUserByUsername("before") }
    }

    @Test
    fun recreatingUsernameGetsNewIdentityAndDoesNotInheritAuthorities() {
        users.createUser(user("reused"))
        val first = users.loadUserByUsername("reused")
        users.deleteUser("reused")
        assertFailsWith<UsernameNotFoundException> { users.loadUserById(first.userId) }
        users.createUser(User.withUsername("reused").password("{noop}password").roles("OTHER").build())
        val second = users.loadUserByUsername("reused")
        assertNotEquals(first.userId, second.userId)
        assertEquals(listOf("ROLE_OTHER"), second.authorities.map { it.authority })
    }

    @Test
    fun duplicateUsernameAndRenameCollisionAreRejected() {
        users.createUser(user("first"))
        users.createUser(user("second"))
        assertFailsWith<DataIntegrityViolationException> { users.createUser(user("first")) }
        val second = users.loadUserByUsername("second")
        assertFailsWith<DataIntegrityViolationException> { users.renameUser(second.userId, "first") }
        assertEquals(second.userId, users.loadUserByUsername("second").userId)
    }

    @Test
    fun passwordChangeUsesStableSessionIdentityAndVerifiesOldPassword() {
        users.createUser(user("password-user"))
        val user = users.loadUserByUsername("password-user")
        users.renameUser(user.userId, "renamed-password-user")
        SecurityContextHolder.getContext().authentication =
            UsernamePasswordAuthenticationToken.authenticated(user.userId, null, user.authorities)
        try {
            assertFailsWith<BadCredentialsException> { users.changePassword("wrong", "{noop}changed") }
            assertEquals("{noop}password", users.loadUserById(user.userId).password)
            users.changePassword("password", "{noop}changed")
            assertEquals("{noop}changed", users.loadUserById(user.userId).password)
        } finally {
            SecurityContextHolder.clearContext()
        }
    }

    private fun user(username: String) = User.withUsername(username).password("{noop}password").roles("USER").build()
}
