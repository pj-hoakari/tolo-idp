package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.user.IdpUserDetails
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

@Tag("unit")
class LoginSessionTests {
    private val clock = Clock.fixed(Instant.parse("2026-11-13T00:00:00Z"), ZoneOffset.UTC)
    private val user = IdpUserDetails(
        id = "71c68dc1-2c72-45ac-a191-1c47c1551011",
        tenantId = "tenant-a",
        delegate = User.withUsername("user-123").password("{noop}secret").roles("USER").build(),
    )

    @AfterEach
    fun clearSecurityContext() {
        SecurityContextHolder.clearContext()
    }

    @Test
    fun storesAnAuthenticatedPasswordSessionInTheRequestSession() {
        val request = MockHttpServletRequest().apply { setRequestedSessionIdValid(false) }

        establishLoginSession(request, user, LOGIN_ID, clock)

        val session = checkNotNull(request.getSession(false))
        val context = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)
            as SecurityContext
        val authentication = checkNotNull(context.authentication)
        assertTrue(authentication.isAuthenticated)
        assertSame(context, SecurityContextHolder.getContext())
    }

    @Test
    fun usesTheUserSurrogateIdAsPrincipalAndClearsCredentials() {
        val request = MockHttpServletRequest().apply { setRequestedSessionIdValid(false) }

        establishLoginSession(request, user, LOGIN_ID, clock)

        val authentication = checkNotNull(SecurityContextHolder.getContext().authentication)
        assertEquals(user.id, authentication.principal)
        assertEquals(user.id, authentication.name)
        assertNull(authentication.credentials)
    }

    @Test
    fun recordsPasswordFactorAndUserAuthorities() {
        val request = MockHttpServletRequest().apply { setRequestedSessionIdValid(false) }

        establishLoginSession(request, user, LOGIN_ID, clock)

        val authorities = checkNotNull(SecurityContextHolder.getContext().authentication).authorities.map { it.authority }
        assertTrue(authorities.contains("ROLE_USER"))
        assertTrue(authorities.contains(FactorGrantedAuthority.PASSWORD_AUTHORITY))
    }

    @Test
    fun recordsAuthenticationTimeAndLoginId() {
        val request = MockHttpServletRequest().apply { setRequestedSessionIdValid(false) }

        establishLoginSession(request, user, LOGIN_ID, clock)

        val details = checkNotNull(SecurityContextHolder.getContext().authentication).details as Map<*, *>
        assertEquals(clock.instant().epochSecond.toString(), details[OidcAuthenticationRequestValidator.AUTH_TIME])
        assertEquals(LOGIN_ID, details[OidcAuthenticationRequestValidator.LOGIN_ID])
    }

    @Test
    fun rotatesTheSessionIdWhenAnExistingSessionIsPresented() {
        val request = MockHttpServletRequest()
        val session = checkNotNull(request.getSession(true))
        request.setRequestedSessionIdValid(true)
        val originalSessionId = session.id

        establishLoginSession(request, user, LOGIN_ID, clock)

        assertNotEquals(originalSessionId, session.id)
    }

    @Test
    fun keepsTheSessionIdWhenTheRequestHasNoExistingSession() {
        val request = MockHttpServletRequest()
        val session = checkNotNull(request.getSession(true))
        request.setRequestedSessionIdValid(false)
        val originalSessionId = session.id

        establishLoginSession(request, user, LOGIN_ID, clock)

        assertEquals(originalSessionId, session.id)
    }

    private companion object {
        const val LOGIN_ID = "login-1"
    }
}
