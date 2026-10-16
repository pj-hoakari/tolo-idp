package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.config.synchronizeTestClients
import dev.usbharu.toloidp.config.RegisteredClientConfigurationSynchronizer
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "server.address=127.0.0.1",
        "spring.datasource.url=jdbc:h2:mem:client-removal-http;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
    ],
)
class TokenIntrospectionClientRemovalTests(
    @LocalServerPort private val port: Int,
    @Autowired private val synchronizer: RegisteredClientConfigurationSynchronizer,
    @Autowired private val properties: OAuth2AuthorizationServerProperties,
    @Autowired private val clients: RegisteredClientRepository,
    @Autowired private val authorizations: OAuth2AuthorizationService,
    @Autowired private val consents: OAuth2AuthorizationConsentService,
    @Autowired private val passwordEncoder: PasswordEncoder,
    @Autowired private val jdbc: JdbcTemplate,
) {
    @BeforeEach
    fun setUp() {
        jdbc.update("DELETE FROM oauth2_authorization")
        jdbc.update("DELETE FROM oauth2_authorization_consent")
        jdbc.update("DELETE FROM oauth2_registered_client")
        synchronizer.synchronizeTestClients(properties.client)
    }

    @Test
    fun deletedClientsTokensReturnInactiveOverHttpAndOtherClientsDataIsPreserved() {
        val removed = managedClient()
        val retained = checkNotNull(clients.findByClientId("client-123"))
        val unmanaged = registeredClient("runtime-client")
        clients.save(unmanaged)
        saveAuthorization(removed, "removed-active", Instant.now().plusSeconds(900))
        saveAuthorization(removed, "removed-expired", Instant.now().minusSeconds(60))
        saveAuthorization(retained, "retained-active", Instant.now().plusSeconds(900))
        saveAuthorization(unmanaged, "runtime-active", Instant.now().plusSeconds(900))
        listOf(removed, retained, unmanaged).forEach { client ->
            consents.save(OAuth2AuthorizationConsent.withId(client.id, "fixture-user").scope("tenant.read").build())
        }
        assertActive("removed-active")

        synchronizer.synchronizeTestClients(properties.client)

        assertNull(clients.findByClientId(removed.clientId))
        assertNull(authorizations.findByToken("removed-active", OAuth2TokenType.ACCESS_TOKEN))
        assertNull(authorizations.findByToken("removed-expired", OAuth2TokenType.ACCESS_TOKEN))
        assertNull(consents.findById(removed.id, "fixture-user"))
        assertInactive("removed-active")
        assertInactive("removed-expired")
        assertInactive("unknown-token")
        listOf(retained, unmanaged).forEach { client ->
            assertNotNull(clients.findByClientId(client.clientId))
            assertNotNull(consents.findById(client.id, "fixture-user"))
        }
        assertActive("retained-active")
        assertActive("runtime-active")

        val replacement = OAuth2AuthorizationServerProperties.Client().apply {
            registration.clientId = "replacement-client"
            registration.clientSecret = "dummy-secret"
            registration.clientAuthenticationMethods = linkedSetOf("client_secret_basic")
            registration.authorizationGrantTypes = linkedSetOf("client_credentials")
        }
        synchronizer.synchronizeTestClients(properties.client + (REGISTRATION_ID to replacement))
        val newClient = checkNotNull(clients.findByClientId("replacement-client"))
        assertNull(consents.findById(newClient.id, "fixture-user"))
        assertInactive("removed-active")
    }

    @Test
    fun changingClientIdUnderTheSameKeyCleansUpOldTokensAndConsent() {
        val initial = replacementConfiguration("old-client")
        synchronizer.synchronizeTestClients(properties.client + (REGISTRATION_ID to initial))
        val old = checkNotNull(clients.findByClientId("old-client"))
        assertEquals(REGISTRATION_ID, old.id)
        val retained = checkNotNull(clients.findByClientId("client-123"))
        saveAuthorization(old, "renamed-token", Instant.now().plusSeconds(900))
        saveAuthorization(retained, "retained-token", Instant.now().plusSeconds(900))
        listOf(old, retained).forEach { client ->
            consents.save(OAuth2AuthorizationConsent.withId(client.id, "fixture-user").scope("tenant.read").build())
        }
        assertActive("renamed-token")

        synchronizer.synchronizeTestClients(properties.client + (REGISTRATION_ID to replacementConfiguration("new-client")))

        assertNull(clients.findByClientId("old-client"))
        val replacement = checkNotNull(clients.findByClientId("new-client"))
        assertEquals(REGISTRATION_ID, replacement.id)
        assertNull(authorizations.findByToken("renamed-token", OAuth2TokenType.ACCESS_TOKEN))
        assertNull(consents.findById(replacement.id, "fixture-user"))
        assertInactive("renamed-token")
        assertNotNull(consents.findById(retained.id, "fixture-user"))
        assertActive("retained-token")
    }

    @Test
    fun failedReplacementRollsBackClientAuthorizationAndConsentDeletion() {
        synchronizer.synchronizeTestClients(properties.client + (REGISTRATION_ID to replacementConfiguration("old-client")))
        val old = checkNotNull(clients.findByClientId("old-client"))
        saveAuthorization(old, "replacement-rollback-token", Instant.now().plusSeconds(900))
        consents.save(OAuth2AuthorizationConsent.withId(old.id, "fixture-user").scope("tenant.read").build())
        val invalid = replacementConfiguration("new-client").apply {
            registration.authorizationGrantTypes = linkedSetOf("authorization_code")
            // RegisteredClient requires a redirect URI for the authorization code grant.
            registration.redirectUris = linkedSetOf()
        }

        assertFailsWith<IllegalArgumentException> {
            synchronizer.synchronizeTestClients(properties.client + (REGISTRATION_ID to invalid))
        }

        assertEquals(old, clients.findByClientId("old-client"))
        assertNull(clients.findByClientId("new-client"))
        assertNotNull(consents.findById(old.id, "fixture-user"))
        assertActive("replacement-rollback-token")
    }

    private fun replacementConfiguration(clientId: String): OAuth2AuthorizationServerProperties.Client =
        OAuth2AuthorizationServerProperties.Client().apply {
            registration.clientId = clientId
            registration.clientSecret = "dummy-secret"
            registration.clientAuthenticationMethods = linkedSetOf("client_secret_basic")
            registration.authorizationGrantTypes = linkedSetOf("client_credentials")
            registration.scopes = linkedSetOf("tenant.read")
        }

    @Test
    fun deletionFailureRollsBackAuthorizationAndConsentCleanup() {
        val removed = managedClient()
        saveAuthorization(removed, "rollback-token", Instant.now().plusSeconds(900))
        consents.save(OAuth2AuthorizationConsent.withId(removed.id, "fixture-user").scope("tenant.read").build())
        jdbc.execute(
            "CREATE TABLE deletion_blocker (client_id varchar(100) REFERENCES oauth2_registered_client(id))",
        )
        try {
            jdbc.update("INSERT INTO deletion_blocker(client_id) VALUES (?)", removed.id)
            assertFailsWith<org.springframework.dao.DataIntegrityViolationException> {
                synchronizer.synchronizeTestClients(properties.client)
            }
            assertNotNull(clients.findByClientId(removed.clientId))
            assertNotNull(authorizations.findByToken("rollback-token", OAuth2TokenType.ACCESS_TOKEN))
            assertNotNull(consents.findById(removed.id, "fixture-user"))
            assertActive("rollback-token")
        } finally {
            jdbc.execute("DROP TABLE deletion_blocker")
        }
    }

    private fun managedClient(): RegisteredClient {
        // Existing JDBC clients may have an internal UUID unrelated to the configuration key.
        val existing = registeredClient("removed-client")
        clients.save(existing)
        val config = OAuth2AuthorizationServerProperties.Client().apply {
            registration.clientId = existing.clientId
            registration.clientSecret = "dummy-secret"
            registration.clientAuthenticationMethods = linkedSetOf("client_secret_basic")
            registration.authorizationGrantTypes = linkedSetOf("client_credentials")
        }
        synchronizer.synchronizeTestClients(properties.client + (REGISTRATION_ID to config))
        return checkNotNull(clients.findByClientId(existing.clientId)).also { assertEquals(existing.id, it.id) }
    }

    private fun registeredClient(clientId: String): RegisteredClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(passwordEncoder.encode("dummy-secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("tenant.read")
            .build()

    private fun saveAuthorization(client: RegisteredClient, token: String, expiresAt: Instant) {
        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, token, expiresAt.minusSeconds(900), expiresAt, setOf("tenant.read"),
        )
        authorizations.save(
            OAuth2Authorization.withRegisteredClient(client)
                .principalName("fixture-user")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(setOf("tenant.read"))
                .token(accessToken) { metadata ->
                    metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = linkedMapOf(
                        "sub" to "fixture-user", "client_id" to client.clientId, "scope" to "tenant.read",
                    )
                }
                .build(),
        )
    }

    private fun assertInactive(token: String) {
        val response = introspect(token)
        assertEquals(200, response.statusCode())
        assertEquals("{\"active\":false}", response.body())
    }

    private fun assertActive(token: String) {
        val response = introspect(token)
        assertEquals(200, response.statusCode())
        assertTrue(response.body().contains("\"active\":true"))
    }

    private fun introspect(token: String): HttpResponse<String> =
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build().use { http ->
            val credentials = Base64.getEncoder().encodeToString("client-123:secret".toByteArray(Charsets.UTF_8))
            val request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port/oauth2/introspect"))
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Basic $credentials")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("token=$token"))
                .build()
            http.send(request, HttpResponse.BodyHandlers.ofString())
        }

    private companion object {
        const val REGISTRATION_ID = "removed-registration"
    }
}
