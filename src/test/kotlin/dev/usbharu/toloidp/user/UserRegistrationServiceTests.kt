package dev.usbharu.toloidp.user

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.transaction.annotation.Transactional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

@SpringBootTest(
    properties = [
        "tolo-idp.seed.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:user-registration;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;DATABASE_TO_UPPER=false",
    ],
)
@Transactional
class UserRegistrationServiceTests(
    @Autowired private val registration: UserRegistrationService,
    @Autowired private val passwordEncoder: PasswordEncoder,
) {
    @Test
    fun createsAUserWithTheSameShapeAsTheSignupApi() {
        val id = UUID.randomUUID().toString()

        val user = registration.create("tenant-a", "owner-1", "correct horse", id)

        assertEquals(id, user.id)
        assertEquals("tenant-a", user.tenantId)
        assertEquals("owner-1", user.username)
        assertTrue(user.isEnabled)
        assertEquals(listOf("ROLE_USER"), user.authorities.map { it.authority })
        assertTrue(passwordEncoder.matches("correct horse", user.password))
        assertNotEquals("correct horse", user.password)
    }

    @Test
    fun generatesACanonicalUuidWhenTheIdIsOmitted() {
        val user = registration.create("tenant-a", "generated-user", "correct horse")

        assertEquals(4, UUID.fromString(user.id).version())
        assertEquals(user.id, UUID.fromString(user.id).toString())
    }

    @Test
    fun rejectsValuesTheSignupApiWouldReject() {
        assertFailsWith<IllegalArgumentException> {
            registration.create("invalid tenant", "user", "correct horse")
        }
        assertFailsWith<IllegalArgumentException> {
            registration.create("tenant-a", "has space", "correct horse")
        }
        assertFailsWith<IllegalArgumentException> {
            registration.create("tenant-a", "user", "short")
        }
        assertFailsWith<IllegalArgumentException> {
            registration.create("tenant-a", "user", "a".repeat(73))
        }
        assertFailsWith<IllegalArgumentException> {
            registration.create("tenant-a", "user", "correct horse", "not-a-uuid")
        }
    }

    @Test
    fun rejectsADuplicateUsernameInTheSameTenantAndAllowsItInAnotherTenant() {
        registration.create("tenant-a", "same-name", "correct horse")

        assertFailsWith<UserAlreadyExistsException> {
            registration.create("tenant-a", "same-name", "correct horse")
        }
        val otherTenant = registration.create("tenant-b", "same-name", "correct horse")
        assertEquals("tenant-b", otherTenant.tenantId)
    }
}
