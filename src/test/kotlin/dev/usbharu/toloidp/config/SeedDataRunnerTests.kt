package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.scope.IdpScopes
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.DefaultApplicationArguments
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.provisioning.UserDetailsManager
import java.util.UUID
import kotlin.test.assertEquals
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
    @Autowired private val policies: ClientPolicyRepository,
    @Autowired private val users: UserDetailsManager,
    @Autowired private val passwordEncoder: PasswordEncoder,
    @Autowired private val jdbc: JdbcClient,
) {
    @BeforeEach
    fun clearSeedData() {
        policies.deleteAll()
        jdbc.sql("delete from oauth2_registered_client").update()
        if (users.userExists("user-123")) {
            users.deleteUser("user-123")
        }
    }

    @Test
    fun createsDevelopmentUserAndClientPolicyAndIsIdempotent() {
        runSeed()
        val firstPolicy = checkNotNull(policies.findByClientId("client-123"))
        assertEquals(IdpScopes.SUPPORTED, firstPolicy.allowedScopes)
        assertTrue(users.userExists("user-123"))
        assertNull(registeredClients.findByClientId("client-123"))

        runSeed()
        assertEquals(firstPolicy, policies.findByClientId("client-123"))
        assertEquals(1L, policies.count())
        assertEquals(0L, jdbc.sql("select count(*) from oauth2_registered_client").query(Long::class.java).single())
    }

    @Test
    fun preservesExistingClientPolicy() {
        runSeed()
        val existingPolicy = checkNotNull(policies.findByClientId("client-123"))
            .copy(
                allowedScopes = setOf("openid"),
                allowedAudiences = setOf("custom-api"),
            )
            .apply { isNewEntity = false }
        policies.save(existingPolicy)

        runSeed()

        assertEquals(existingPolicy, policies.findByClientId("client-123"))
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
    }

    @Test
    fun disabledSeedDoesNotCreateData() {
        runSeed(enabled = false)
        assertNull(registeredClients.findByClientId("client-123"))
        assertNull(policies.findByClientId("client-123"))
        assertFalse(users.userExists("user-123"))
    }

    @Test
    fun leavesOtherClientPoliciesUnchanged() {
        runSeed()
        val otherPolicy = checkNotNull(policies.findByClientId("client-123")).copy(clientId = "other-client")
        policies.save(otherPolicy)

        runSeed(enabled = false)
        assertEquals(otherPolicy, policies.findByClientId("other-client"))

        runSeed()
        assertEquals(otherPolicy, policies.findByClientId("other-client"))
        assertTrue(users.userExists("user-123"))
    }

    private fun runSeed(enabled: Boolean = true) {
        SeedDataRunner(
            IdpProperties(seed = IdpProperties.Seed(enabled = enabled)),
            passwordEncoder,
            users,
            policies,
        ).run(DefaultApplicationArguments())
    }
}
