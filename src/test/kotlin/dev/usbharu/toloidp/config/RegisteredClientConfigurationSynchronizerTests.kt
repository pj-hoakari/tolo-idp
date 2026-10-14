package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.scope.IdpScopes
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Duration
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(
    properties = [
        "spring.datasource.url=jdbc:h2:mem:registered-client-sync;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;DATABASE_TO_UPPER=false",
    ],
)
class RegisteredClientConfigurationSynchronizerTests(
    @Autowired private val synchronizer: RegisteredClientConfigurationSynchronizer,
    @Autowired private val properties: OAuth2AuthorizationServerProperties,
    @Autowired private val registeredClientRepository: RegisteredClientRepository,
    @Autowired private val passwordEncoder: PasswordEncoder,
    @Autowired private val jdbcTemplate: JdbcTemplate,
) {
    @BeforeEach
    fun setUp() {
        jdbcTemplate.update("DELETE FROM oauth2_registered_client")
        synchronizer.synchronizeTestClients(properties.client)
    }

    @Test
    fun configuredDevelopmentClientIsSyncedAndManaged() {
        val client = registeredClientRepository.findByClientId("client-123")

        assertNotNull(client)
        assertEquals("client-123", client.id)
        assertEquals(
            setOf(
                "http://127.0.0.1:8080/login/oauth2/code/client-123",
                "http://127.0.0.1:18080/login/oauth2/code/client-123",
                "http://localhost:3000/api/auth/callback/tolo-idp",
            ),
            client.redirectUris,
        )
        assertEquals(IdpScopes.SUPPORTED, client.scopes)
        assertEquals(
            setOf(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST),
            client.clientAuthenticationMethods,
        )
        assertEquals(
            setOf(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.TOKEN_EXCHANGE),
            client.authorizationGrantTypes,
        )
        assertEquals(Duration.ofMinutes(15), client.tokenSettings.accessTokenTimeToLive)
        assertEquals(OAuth2TokenFormat.SELF_CONTAINED, client.tokenSettings.accessTokenFormat)
        assertTrue(client.clientSettings.isRequireProofKey)
        assertFalse(client.clientSettings.isRequireAuthorizationConsent)
        assertTrue(passwordEncoder.matches("secret", client.clientSecret))
        assertTrue(isConfigurationManaged("client-123"))
    }

    @Test
    fun keepsExistingIdAndReplacesRedirectUrisAndScopes() {
        val existingId = UUID.randomUUID().toString()
        val existingSecret = passwordEncoder.encode("legacy-secret")
        registeredClientRepository.save(
            RegisteredClient.withId(existingId)
                .clientId("legacy-client")
                .clientSecret(existingSecret)
                .clientName("Legacy")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:8080/old")
                .redirectUri("http://127.0.0.1:8080/also-old")
                .scope("openid")
                .scope("extra.scope")
                .build(),
        )

        synchronizer.synchronizeTestClients(
            mapOf(
                "legacy-registration" to configuredClient(
                    clientId = "legacy-client",
                    clientSecret = "legacy-secret",
                    redirectUris = setOf("https://example.com/callback"),
                    scopes = setOf("openid"),
                ),
            ),
        )

        val updated = registeredClientRepository.findByClientId("legacy-client")
        assertNotNull(updated)
        assertEquals(existingId, updated.id)
        assertEquals(setOf("https://example.com/callback"), updated.redirectUris)
        assertEquals(setOf("openid"), updated.scopes)
        assertEquals(existingSecret, updated.clientSecret)
        assertTrue(isConfigurationManaged("legacy-client"))
        assertNull(registeredClientRepository.findByClientId("client-123"))
    }

    @Test
    fun keepsPlaintextSecretHashUntilTheSecretChanges() {
        synchronizer.synchronizeTestClients(mapOf("secret-client" to configuredClient(clientId = "secret-client", clientSecret = "plain-secret")))
        val firstSecret = registeredClientRepository.findByClientId("secret-client")?.clientSecret

        synchronizer.synchronizeTestClients(mapOf("secret-client" to configuredClient(clientId = "secret-client", clientSecret = "plain-secret")))
        val secondSecret = registeredClientRepository.findByClientId("secret-client")?.clientSecret

        assertNotNull(firstSecret)
        assertEquals(firstSecret, secondSecret)
        assertTrue(passwordEncoder.matches("plain-secret", secondSecret))

        synchronizer.synchronizeTestClients(mapOf("secret-client" to configuredClient(clientId = "secret-client", clientSecret = "other-secret")))
        val changedSecret = registeredClientRepository.findByClientId("secret-client")?.clientSecret

        assertNotNull(changedSecret)
        assertNotEquals(firstSecret, changedSecret)
        assertTrue(passwordEncoder.matches("other-secret", changedSecret))
        assertFalse(passwordEncoder.matches("plain-secret", changedSecret))
    }

    @Test
    fun storesEncodedSecretAsProvided() {
        synchronizer.synchronizeTestClients(
            mapOf("encoded-client" to configuredClient(clientId = "encoded-client", clientSecret = "{noop}top-secret")),
        )

        assertEquals("{noop}top-secret", registeredClientRepository.findByClientId("encoded-client")?.clientSecret)
    }

    @ParameterizedTest
    @MethodSource("missingSecrets")
    fun rejectsMissingSecretWithoutChangingExistingCredentials(method: String, secret: String?) {
        synchronizer.synchronizeTestClients(
            properties.client + ("secret-client" to configuredClient(
                clientId = "secret-client",
                clientSecret = "original-secret",
                authenticationMethods = setOf(method),
            )),
        )
        val before = checkNotNull(registeredClientRepository.findByClientId("secret-client"))

        assertFailsWith<IllegalStateException> {
            synchronizer.synchronizeTestClients(
                linkedMapOf(
                    "new-valid-client" to configuredClient(clientId = "new-valid-client"),
                    "secret-client" to configuredClient(
                        clientId = "secret-client", clientSecret = secret, authenticationMethods = setOf(method),
                    ),
                ),
            )
        }

        val after = checkNotNull(registeredClientRepository.findByClientId("secret-client"))
        assertEquals(before, after)
        assertTrue(passwordEncoder.matches("original-secret", after.clientSecret))
        assertNull(registeredClientRepository.findByClientId("new-valid-client"))
        assertNotNull(registeredClientRepository.findByClientId("client-123"))
    }

    @ParameterizedTest
    @MethodSource("missingSecrets")
    fun rejectsNewSecretBasedClientWithoutSecret(method: String, secret: String?) {
        assertFailsWith<IllegalStateException> {
            synchronizer.synchronizeTestClients(
                mapOf("invalid-client" to configuredClient(
                    clientId = "invalid-client", clientSecret = secret, authenticationMethods = setOf(method),
                )),
            )
        }

        assertNull(registeredClientRepository.findByClientId("invalid-client"))
        assertNotNull(registeredClientRepository.findByClientId("client-123"))
    }

    @ParameterizedTest
    @ValueSource(strings = ["none", "private_key_jwt"])
    fun permitsClientsWithoutSecretWhenAuthenticationDoesNotUseIt(method: String) {
        synchronizer.synchronizeTestClients(
            properties.client + ("secretless-client" to configuredClient(
                clientId = "secretless-client", clientSecret = null, authenticationMethods = setOf(method),
            )),
        )

        val client = checkNotNull(registeredClientRepository.findByClientId("secretless-client"))
        assertNull(client.clientSecret)
        assertEquals(setOf(ClientAuthenticationMethod(method)), client.clientAuthenticationMethods)
    }

    @Test
    fun rejectsMissingSecretEvenWhenAnotherAuthenticationMethodDoesNotNeedIt() {
        assertFailsWith<IllegalStateException> {
            synchronizer.synchronizeTestClients(
                mapOf("mixed-client" to configuredClient(
                    clientId = "mixed-client", clientSecret = null,
                    authenticationMethods = setOf("private_key_jwt", "client_secret_basic"),
                )),
            )
        }
        assertNull(registeredClientRepository.findByClientId("mixed-client"))
    }

    @Test
    fun deletesConfigurationManagedClientsRemovedFromConfiguration() {
        synchronizer.synchronizeTestClients(mapOf("temp" to configuredClient(clientId = "removed-client")))
        assertTrue(isConfigurationManaged("removed-client"))

        synchronizer.synchronizeTestClients(properties.client)

        assertNull(registeredClientRepository.findByClientId("removed-client"))
        assertNotNull(registeredClientRepository.findByClientId("client-123"))
    }

    @Test
    fun leavesUnmanagedClientsInPlace() {
        registeredClientRepository.save(
            RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("runtime-client")
                .clientSecret(passwordEncoder.encode("runtime-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("openid")
                .build(),
        )

        synchronizer.synchronizeTestClients(properties.client)

        assertNotNull(registeredClientRepository.findByClientId("runtime-client"))
        assertFalse(isConfigurationManaged("runtime-client"))
        assertNotNull(registeredClientRepository.findByClientId("client-123"))
    }

    @Test
    fun duplicateClientIdIsRejectedWithoutSaving() {
        val failure = assertFailsWith<IllegalStateException> {
            synchronizer.synchronizeTestClients(
                mapOf(
                    "first" to configuredClient(clientId = "same-client"),
                    "second" to configuredClient(clientId = "same-client"),
                ),
            )
        }

        assertTrue(failure.message!!.contains("same-client"))
        assertNull(registeredClientRepository.findByClientId("same-client"))
        assertNotNull(registeredClientRepository.findByClientId("client-123"))
    }

    @Test
    fun registrationIdCollisionIsRejectedWithoutSaving() {
        registeredClientRepository.save(
            RegisteredClient.withId("taken-id")
                .clientId("existing-client")
                .clientSecret(passwordEncoder.encode("existing-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("openid")
                .build(),
        )

        assertFailsWith<IllegalStateException> {
            synchronizer.synchronizeTestClients(mapOf("taken-id" to configuredClient(clientId = "other-client")))
        }

        assertNull(registeredClientRepository.findByClientId("other-client"))
        assertNotNull(registeredClientRepository.findByClientId("existing-client"))
        assertNotNull(registeredClientRepository.findByClientId("client-123"))
    }

    private fun isConfigurationManaged(clientId: String): Boolean =
        jdbcTemplate.queryForObject(
            "SELECT configuration_managed FROM oauth2_registered_client WHERE client_id = ?",
            Boolean::class.java,
            clientId,
        ) == true

    private fun configuredClient(
        clientId: String,
        clientSecret: String? = "secret",
        redirectUris: Set<String> = setOf("http://127.0.0.1:8080/callback"),
        scopes: Set<String> = setOf("openid"),
        authenticationMethods: Set<String> = setOf("client_secret_basic"),
    ): OAuth2AuthorizationServerProperties.Client {
        val client = OAuth2AuthorizationServerProperties.Client()
        client.registration.clientId = clientId
        client.registration.clientSecret = clientSecret
        client.registration.clientName = clientId
        client.registration.clientAuthenticationMethods = authenticationMethods.toCollection(linkedSetOf())
        client.registration.authorizationGrantTypes = linkedSetOf("authorization_code")
        client.registration.redirectUris = redirectUris.toCollection(linkedSetOf())
        client.registration.scopes = scopes.toCollection(linkedSetOf())
        client.isRequireProofKey = false
        client.isRequireAuthorizationConsent = false
        return client
    }

    private companion object {
        @JvmStatic
        fun missingSecrets(): List<Arguments> =
            listOf("client_secret_basic", "client_secret_post", "client_secret_jwt").flatMap { method ->
                listOf(null, "", " \t ").map { secret -> Arguments.of(method, secret) }
            }
    }
}
