package dev.usbharu.toloidp.user

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.springframework.security.core.userdetails.User
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Tag("unit")
class IdpUserDetailsTests {
    @Test
    fun delegatesEnabledAndAccountStatusFlags() {
        val active = IdpUserDetails(
            "id-active",
            "tenant-a",
            User.withUsername("active").password("{noop}password").roles("USER").build(),
        )
        assertEquals("id-active", active.id)
        assertEquals("tenant-a", active.tenantId)
        assertTrue(active.isEnabled)
        assertTrue(active.isAccountNonExpired)
        assertTrue(active.isAccountNonLocked)
        assertTrue(active.isCredentialsNonExpired)

        val blocked = IdpUserDetails(
            "id-blocked",
            "tenant-a",
            User.withUsername("blocked").password("{noop}password").roles("USER")
                .disabled(true)
                .accountExpired(true)
                .accountLocked(true)
                .credentialsExpired(true)
                .build(),
        )
        assertFalse(blocked.isEnabled)
        assertFalse(blocked.isAccountNonExpired)
        assertFalse(blocked.isAccountNonLocked)
        assertFalse(blocked.isCredentialsNonExpired)
    }
}
