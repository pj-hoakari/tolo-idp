package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import tools.jackson.databind.ObjectMapper
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:login-challenges;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
class LoginChallengesTests(
    @Autowired private val jdbc: JdbcTemplate,
    @Autowired private val json: ObjectMapper,
) {
    private val issuedAt = Instant.parse("2026-10-31T00:00:00Z")
    private val request = mapOf("client_id" to arrayOf("client-123"), "nonce" to arrayOf(" a b ", "+"))

    @Test
    fun pendingChallengeCannotBeAuthenticatedTenMinutesAfterIssue() {
        val challenge = at(Duration.ZERO).issue("client-123", "tenant-a", request)!!
        assertEquals("tenant-a", at(Duration.ofSeconds(599)).tenant(challenge))
        assertNull(at(Duration.ofMinutes(10)).tenant(challenge))
        assertFalse(at(Duration.ofMinutes(10)).authenticate(challenge, "login-1", "subject"))
    }

    @Test
    fun authenticatedChallengeCannotResumeTenMinutesAfterIssue() {
        val challenge = at(Duration.ZERO).issue("client-123", "tenant-a", request)!!
        assertTrue(at(Duration.ofSeconds(599)).authenticate(challenge, "login-1", "subject"))
        assertNull(at(Duration.ofMinutes(10)).consume(challenge, "login-1"))
    }

    @Test
    fun authenticatedChallengeResumesTheStoredRequestOnceForItsLogin() {
        val challenge = at(Duration.ZERO).issue("client-123", "tenant-a", request)!!
        assertNull(at(Duration.ofMinutes(1)).consume(challenge, "login-1"))
        assertTrue(at(Duration.ofMinutes(1)).authenticate(challenge, "login-1", "subject"))
        assertFalse(at(Duration.ofMinutes(1)).authenticate(challenge, "login-2", "subject"))
        assertNull(at(Duration.ofMinutes(2)).tenant(challenge))
        assertNull(at(Duration.ofMinutes(2)).consume(challenge, "login-2"))
        assertNull(at(Duration.ofMinutes(2)).consume(challenge, null))
        assertEquals(request.mapValues { it.value.toList() }, at(Duration.ofMinutes(2)).consume(challenge, "login-1"))
        assertNull(at(Duration.ofMinutes(2)).consume(challenge, "login-1"))
    }

    @Test
    fun oversizedAuthorizationRequestIsNotStored() {
        assertNull(at(Duration.ZERO).issue("client-123", "tenant-a", mapOf("padding" to arrayOf("x".repeat(9000)))))
    }

    private fun at(offset: Duration) = LoginChallenges(jdbc, json, Clock.fixed(issuedAt.plus(offset), ZoneOffset.UTC))
}
