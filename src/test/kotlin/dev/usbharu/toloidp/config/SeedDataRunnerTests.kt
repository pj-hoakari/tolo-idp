package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicyRepository
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.DefaultApplicationArguments
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.provisioning.UserDetailsManager
import java.time.Duration
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
    private val expectedScopes = setOf(
        "openid", "tenant.read", "tenant.write", "tenant.claim",
        "events.read", "events.manage", "events.operate", "events.report",
    )

    @BeforeEach
    fun clearSeedData() {
        policies.deleteAll()
        jdbc.sql("delete from oauth2_registered_client").update()
        if (users.userExists("user-123")) {
            users.deleteUser("user-123")
        }
    }

    @Test
    fun createsDevelopmentClientWithAllSupportedScopesAndIsIdempotent() {
        runSeed()
        val firstClient = checkNotNull(registeredClients.findByClientId("client-123"))
        val firstPolicy = checkNotNull(policies.findByClientId("client-123"))
        assertEquals(expectedScopes, firstClient.scopes)
        assertEquals(expectedScopes, firstPolicy.allowedScopes)

        runSeed()
        val secondClient = checkNotNull(registeredClients.findByClientId("client-123"))
        assertEquals(firstClient.id, secondClient.id)
        assertEquals(firstClient.clientSecret, secondClient.clientSecret)
        assertEquals(firstPolicy, policies.findByClientId("client-123"))
        assertEquals(1L, policies.count())
        assertEquals(1L, jdbc.sql("select count(*) from oauth2_registered_client").query(Long::class.java).single())
    }

    @Test
    fun synchronizesExistingScopesPreservingClientAndPolicySettings() {
        runSeed()
        val existingClient = RegisteredClient.from(checkNotNull(registeredClients.findByClientId("client-123")))
            .clientName("Customized development client")
            .scopes { it.clear(); it.addAll(setOf("openid", "events.write")) }
            .redirectUri("https://custom.example.com/callback")
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(3)).build())
            .build()
        registeredClients.save(existingClient)
        val existingPolicy = checkNotNull(policies.findByClientId("client-123"))
            .copy(
                allowedScopes = setOf("openid", "events.write"),
                allowedAudiences = setOf("custom-api"),
                tenantAccessTtl = Duration.ofSeconds(123),
                eventAccessTtl = Duration.ofSeconds(45),
            )
            .apply { isNewEntity = false }
        policies.save(existingPolicy)

        runSeed()
        val updatedClient = checkNotNull(registeredClients.findByClientId("client-123"))
        assertEquals(expectedScopes, updatedClient.scopes)
        assertEquals(existingClient.id, updatedClient.id)
        assertEquals(existingClient.clientName, updatedClient.clientName)
        assertEquals(existingClient.clientSecret, updatedClient.clientSecret)
        assertEquals(existingClient.redirectUris, updatedClient.redirectUris)
        assertEquals(existingClient.authorizationGrantTypes, updatedClient.authorizationGrantTypes)
        assertEquals(existingClient.clientAuthenticationMethods, updatedClient.clientAuthenticationMethods)
        assertEquals(existingClient.clientSettings.settings, updatedClient.clientSettings.settings)
        assertEquals(existingClient.tokenSettings.settings, updatedClient.tokenSettings.settings)
        assertEquals(existingPolicy.copy(allowedScopes = expectedScopes), policies.findByClientId("client-123"))

        runSeed()
        assertEquals(1L, policies.count())
        assertEquals(existingPolicy.copy(allowedScopes = expectedScopes), policies.findByClientId("client-123"))
    }

    @Test
    fun restoresDevelopmentRedirectUrisWhilePreservingCustomRedirects() {
        runSeed()
        val before = checkNotNull(registeredClients.findByClientId("client-123"))
        registeredClients.save(
            RegisteredClient.from(before)
                .redirectUris { it.clear(); it.add("https://custom.example.com/callback") }
                .build(),
        )

        runSeed()
        val after = checkNotNull(registeredClients.findByClientId("client-123"))
        assertEquals(before.redirectUris + "https://custom.example.com/callback", after.redirectUris)
    }

    @Test
    fun disabledSeedDoesNotCreateData() {
        runSeed(enabled = false)
        assertNull(registeredClients.findByClientId("client-123"))
        assertNull(policies.findByClientId("client-123"))
        assertFalse(users.userExists("user-123"))
    }

    @Test
    fun leavesOtherClientsAndDisabledSeedDataUnchanged() {
        runSeed()
        val developmentClient = checkNotNull(registeredClients.findByClientId("client-123"))
        val legacyClient = RegisteredClient.from(developmentClient)
            .scopes { it.clear(); it.add("events.write") }
            .build()
        registeredClients.save(legacyClient)
        val legacyPolicy = checkNotNull(policies.findByClientId("client-123"))
            .copy(allowedScopes = setOf("events.write"))
            .apply { isNewEntity = false }
        policies.save(legacyPolicy)
        registeredClients.save(
            RegisteredClient.from(legacyClient)
                .id("other-client-id")
                .clientId("other-client")
                .clientSecret(passwordEncoder.encode("other-client-secret"))
                .build(),
        )
        policies.save(legacyPolicy.copy(clientId = "other-client"))

        runSeed(enabled = false)
        assertEquals(setOf("events.write"), registeredClients.findByClientId("client-123")!!.scopes)
        assertEquals(legacyPolicy, policies.findByClientId("client-123"))

        runSeed()
        assertEquals(setOf("events.write"), registeredClients.findByClientId("other-client")!!.scopes)
        assertEquals(legacyPolicy.copy(clientId = "other-client"), policies.findByClientId("other-client"))
        assertTrue(users.userExists("user-123"))
    }

    private fun runSeed(enabled: Boolean = true) {
        SeedDataRunner(
            IdpProperties(seed = IdpProperties.Seed(enabled = enabled)),
            passwordEncoder,
            users,
            registeredClients,
            policies,
        ).run(DefaultApplicationArguments())
    }
}
