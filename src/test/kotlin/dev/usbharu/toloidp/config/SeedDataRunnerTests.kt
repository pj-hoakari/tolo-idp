package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.user.IdpUserDetailsManager
import dev.usbharu.toloidp.user.UserRegistrationService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.DefaultApplicationArguments
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.FileSystemResource
import org.springframework.core.io.Resource
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import tools.jackson.databind.json.JsonMapper
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(
    properties = [
        "tolo-idp.seed.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:seed-data-tests;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;DATABASE_TO_UPPER=false",
    ],
)
class SeedDataRunnerTests(
    @Autowired private val registeredClients: RegisteredClientRepository,
    @Autowired private val users: IdpUserDetailsManager,
    @Autowired private val passwordEncoder: PasswordEncoder,
    @Autowired private val registration: UserRegistrationService,
    @Autowired private val json: JsonMapper,
    @Autowired private val jdbc: JdbcClient,
) {
    @TempDir
    lateinit var tempDir: Path

    @BeforeEach
    fun clearSeedData() {
        jdbc.sql("delete from oauth2_registered_client").update()
        jdbc.sql("delete from idp_user_authorities").update()
        jdbc.sql("delete from idp_users").update()
    }

    @Test
    fun createsTestSeedUserOnlyAndIsIdempotent() {
        runSeed()
        val first = users.loadUserByUsername("tenant-a", "user-123")
        assertEquals(IdpUserDetailsManager.DEVELOPMENT_USER_ID, first.id)
        assertEquals("tenant-a", first.tenantId)
        assertEquals("user-123", first.username)
        assertTrue(first.isEnabled)
        assertEquals(listOf("ROLE_USER"), first.authorities.map { it.authority })
        assertTrue(passwordEncoder.matches("password", first.password))

        runSeed()

        val second = users.loadUserByUsername("tenant-a", "user-123")
        assertEquals(first.password, second.password)
        assertEquals(1L, jdbc.sql("select count(*) from idp_users").query(Long::class.java).single())
    }

    @Test
    fun createsDevelopmentUserFromTheDefaultFileInTheToloTenant() {
        runSeed(resource = ClassPathResource("seed/users.json"))

        val user = users.loadUserByUsername("0123456789abcdef", "user-123")
        assertEquals(IdpUserDetailsManager.DEVELOPMENT_USER_ID, user.id)
        assertEquals("0123456789abcdef", user.tenantId)
        assertEquals("user-123", user.username)
        assertTrue(user.isEnabled)
        assertEquals(listOf("ROLE_USER"), user.authorities.map { it.authority })
        assertTrue(passwordEncoder.matches("password", user.password))
        assertFalse(users.userExists("tenant-a", "user-123"))
    }

    @Test
    fun createsMultipleUsersAcrossTenants() {
        val firstId = UUID.randomUUID().toString()
        val secondId = UUID.randomUUID().toString()
        val resource = seedResource(
            seedJson(
                seedUser(id = firstId, tenantId = "tenant-a", username = "user-a", password = "password-a"),
                seedUser(id = secondId, tenantId = "tenant-b", username = "user-b", password = "password-b"),
            ),
        )

        runSeed(resource = resource)

        val first = users.loadUserByUsername("tenant-a", "user-a")
        val second = users.loadUserByUsername("tenant-b", "user-b")
        assertEquals(firstId, first.id)
        assertEquals(secondId, second.id)
        assertTrue(passwordEncoder.matches("password-a", first.password))
        assertTrue(passwordEncoder.matches("password-b", second.password))
        assertEquals(listOf("ROLE_USER"), first.authorities.map { it.authority })
    }

    @Test
    fun rejectsExistingUserWithDifferentId() {
        val existingId = UUID.randomUUID().toString()
        users.createUser("tenant-a", user("user-123", "password"), existingId)

        val resource = seedResource(
            seedJson(seedUser(id = IdpUserDetailsManager.DEVELOPMENT_USER_ID, tenantId = "tenant-a", username = "user-123")),
        )

        assertFailsWith<IllegalStateException> { runSeed(resource = resource) }
        assertEquals(existingId, users.loadUserByUsername("tenant-a", "user-123").id)
    }

    @Test
    fun rejectsExistingUserWithDifferentPassword() {
        users.createUser(
            "tenant-a",
            user("user-123", "another-password"),
            IdpUserDetailsManager.DEVELOPMENT_USER_ID,
        )

        val resource = seedResource(
            seedJson(
                seedUser(
                    id = IdpUserDetailsManager.DEVELOPMENT_USER_ID,
                    tenantId = "tenant-a",
                    username = "user-123",
                    password = "password",
                ),
            ),
        )

        assertFailsWith<IllegalStateException> { runSeed(resource = resource) }
    }

    @Test
    fun rejectsExistingUserWithDifferentAuthorities() {
        users.createUser(
            "tenant-a",
            User.withUsername("user-123").password(passwordEncoder.encode("password")).roles("ADMIN").build(),
            IdpUserDetailsManager.DEVELOPMENT_USER_ID,
        )

        val resource = seedResource(
            seedJson(
                seedUser(
                    id = IdpUserDetailsManager.DEVELOPMENT_USER_ID,
                    tenantId = "tenant-a",
                    username = "user-123",
                    password = "password",
                ),
            ),
        )

        assertFailsWith<IllegalStateException> { runSeed(resource = resource) }
    }

    @Test
    fun rejectsExistingDisabledUser() {
        users.createUser(
            "tenant-a",
            User.withUsername("user-123")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .disabled(true)
                .build(),
            IdpUserDetailsManager.DEVELOPMENT_USER_ID,
        )

        val resource = seedResource(
            seedJson(
                seedUser(
                    id = IdpUserDetailsManager.DEVELOPMENT_USER_ID,
                    tenantId = "tenant-a",
                    username = "user-123",
                    password = "password",
                ),
            ),
        )

        assertFailsWith<IllegalStateException> { runSeed(resource = resource) }
    }

    @Test
    fun rejectsIdUsedByAnotherUser() {
        val sharedId = UUID.randomUUID().toString()
        users.createUser("tenant-a", user("other-user", "password"), sharedId)

        val resource = seedResource(
            seedJson(seedUser(id = sharedId, tenantId = "tenant-a", username = "user-123")),
        )

        assertFailsWith<IllegalStateException> { runSeed(resource = resource) }
        assertFalse(users.userExists("tenant-a", "user-123"))
    }

    @Test
    fun rejectsInvalidSeedEntries() {
        val cases = listOf(
            "missing id" to """{"users":[{"tenantId":"tenant-a","username":"user-123","password":"password"}]}""",
            "invalid id" to seedJson(seedUser(id = "not-a-uuid")),
            "invalid tenant id" to seedJson(seedUser(tenantId = "tenant id")),
            "invalid username" to seedJson(seedUser(username = "has space")),
            "invalid password" to seedJson(seedUser(password = "short")),
            "unknown field" to """{"users":[{"id":"${UUID.randomUUID()}","tenantId":"tenant-a","username":"user-123","password":"password","extra":true}]}""",
            "missing users" to """{}""",
            "malformed json" to """{"users":[""",
            "null user" to """{"users":[null]}""",
            "duplicate id" to duplicateIdJson(),
            "duplicate username" to seedJson(
                seedUser(username = "same"),
                seedUser(username = "same"),
            ),
        )

        cases.forEach { (name, jsonText) ->
            assertFailsWith<IllegalStateException>(name) {
                runSeed(resource = seedResource(jsonText))
            }
        }
    }

    @Test
    fun duplicateIdIsRejectedBeforeAnyUserIsCreated() {
        val duplicateId = UUID.randomUUID().toString()
        val resource = seedResource(
            seedJson(
                seedUser(id = duplicateId, username = "first"),
                seedUser(id = duplicateId, username = "second"),
            ),
        )

        assertFailsWith<IllegalStateException> { runSeed(resource = resource) }
        assertFalse(users.userExists("tenant-a", "first"))
        assertFalse(users.userExists("tenant-a", "second"))
    }

    @Test
    fun doesNotCreateAnyUserWhenOneEntryDoesNotMatch() {
        users.createUser(
            "tenant-a",
            user("existing-user", "password"),
            UUID.randomUUID().toString(),
        )
        val newId = UUID.randomUUID().toString()
        val resource = seedResource(
            seedJson(
                seedUser(id = newId, username = "new-user"),
                seedUser(
                    id = IdpUserDetailsManager.DEVELOPMENT_USER_ID,
                    tenantId = "tenant-a",
                    username = "existing-user",
                    password = "password",
                ),
            ),
        )

        assertFailsWith<IllegalStateException> { runSeed(resource = resource) }
        assertFalse(users.userExists("tenant-a", "new-user"))
    }

    @Test
    fun emptyUsersArrayCreatesNothing() {
        runSeed(resource = seedResource("""{"users":[]}"""))

        assertEquals(0L, jdbc.sql("select count(*) from idp_users").query(Long::class.java).single())
    }

    @Test
    fun disabledSeedDoesNotReadTheUsersFile() {
        runSeed(
            enabled = false,
            resource = FileSystemResource(tempDir.resolve("missing.json")),
        )

        assertFalse(users.userExists("tenant-a", "user-123"))
    }

    @Test
    fun missingUsersFileFailsWhenSeedIsEnabled() {
        assertFailsWith<IllegalStateException> {
            runSeed(resource = FileSystemResource(tempDir.resolve("missing.json")))
        }
    }

    @Test
    fun doesNotIncludePasswordsInRejectionMessages() {
        val password = "super-secret-password"
        val resource = seedResource(
            """{"users":[{"id":"${UUID.randomUUID()}","tenantId":"tenant-a","username":"user-123","password":"$password","extra":true}]}""",
        )

        val failure = assertFailsWith<IllegalStateException> { runSeed(resource = resource) }

        assertFalse(failure.message.orEmpty().contains(password))
    }

    @Test
    fun doesNotModifyRegisteredClients() {
        val client = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client-123")
            .clientSecret(passwordEncoder.encode("secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://custom.example.com/callback")
            .scope("openid")
            .build()
        registeredClients.save(client)

        runSeed()

        val stored = checkNotNull(registeredClients.findByClientId("client-123"))
        assertEquals(client.id, stored.id)
        assertEquals(client.redirectUris, stored.redirectUris)
        assertEquals(client.scopes, stored.scopes)
        assertEquals(client.clientSecret, stored.clientSecret)
        assertNull(registeredClients.findByClientId("unknown"))
    }

    private fun runSeed(
        enabled: Boolean = true,
        resource: Resource = ClassPathResource("seed/test-users.json"),
    ) {
        SeedDataRunner(
            IdpProperties(seed = IdpProperties.Seed(enabled = enabled, usersFile = resource)),
            passwordEncoder,
            users,
            registration,
        ).run(DefaultApplicationArguments())
    }

    private fun seedResource(jsonText: String): Resource {
        val file = tempDir.resolve("users-${UUID.randomUUID()}.json")
        Files.writeString(file, jsonText)
        return FileSystemResource(file)
    }

    private fun seedJson(vararg users: Map<String, String>): String =
        json.writeValueAsString(mapOf("users" to users))

    private fun duplicateIdJson(): String {
        val id = UUID.randomUUID().toString()
        return seedJson(
            seedUser(id = id, username = "first"),
            seedUser(id = id, username = "second"),
        )
    }

    private fun seedUser(
        id: String = UUID.randomUUID().toString(),
        tenantId: String = "tenant-a",
        username: String = "user-${UUID.randomUUID().toString().take(8)}",
        password: String = "password",
    ): Map<String, String> = mapOf(
        "id" to id,
        "tenantId" to tenantId,
        "username" to username,
        "password" to password,
    )

    private fun user(username: String, password: String): UserDetails =
        User.withUsername(username).password(passwordEncoder.encode(password)).roles("USER").build()
}
