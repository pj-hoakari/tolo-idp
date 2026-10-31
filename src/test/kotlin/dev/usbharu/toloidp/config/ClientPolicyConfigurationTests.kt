package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientPolicyConfig
import dev.usbharu.toloidp.client.ClientType
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:client-policy-config;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
])
class ClientPolicyConfigurationTests(
    @Autowired private val synchronizer: RegisteredClientConfigurationSynchronizer,
    @Autowired private val standard: OAuth2AuthorizationServerProperties,
    @Autowired private val custom: IdpProperties,
    @Autowired private val clients: RegisteredClientRepository,
) {
    @BeforeEach
    fun restore() {
        synchronizer.synchronize(standard.client, custom.clients)
    }

    @Test
    fun bindsCustomConfigurationAndPersistsItWithStandardClientFields() {
        val config = custom.clients.getValue("client-123")
        val client = checkNotNull(clients.findByClientId("client-123"))
        val policy = checkNotNull(ClientPolicy.from(client))
        assertEquals(config.allowedAudiences, policy.allowedAudiences)
        assertEquals(config.allowedTokenExchangeTransitions, policy.allowedTransitions)
        assertEquals(config.tenantAccessTtl, policy.tenantAccessTtl)
        assertEquals(config.eventAccessTtl, policy.eventAccessTtl)
        assertEquals(client.scopes, policy.allowedScopes)
        assertEquals(client.authorizationGrantTypes.map { it.value }.toSet(), policy.allowedGrantTypes)
        assertFalse(policy.tokenIntrospectionAllowed)
        val gateway = checkNotNull(ClientPolicy.from(checkNotNull(clients.findByClientId("service-gateway"))))
        assertEquals(ClientType.CONFIDENTIAL, gateway.clientType)
        assertTrue(gateway.tokenIntrospectionAllowed)
    }

    @Test
    fun registrationKeyCanDifferFromClientIdAndPolicyChangesPreserveIdentity() {
        val registration = registration("configured-client")
        val first = ClientPolicyConfig(setOf("api-a"), emptySet(), Duration.ofSeconds(123), Duration.ofSeconds(45))
        synchronizer.synchronize(standard.client + ("web-app" to registration), custom.clients + ("web-app" to first))
        val initial = checkNotNull(clients.findByClientId("configured-client"))
        assertEquals("web-app", initial.id)
        assertEquals(setOf("api-a"), ClientPolicy.from(initial)?.allowedAudiences)
        val updated = first.copy(allowedAudiences = setOf("api-b"), eventAccessTtl = Duration.ofSeconds(67))
        synchronizer.synchronize(standard.client + ("web-app" to registration), custom.clients + ("web-app" to updated))
        val loaded = checkNotNull(clients.findByClientId("configured-client"))
        assertEquals(initial.id, loaded.id)
        assertEquals(initial.clientSecret, loaded.clientSecret)
        assertEquals(setOf("api-b"), ClientPolicy.from(loaded)?.allowedAudiences)
        assertEquals(Duration.ofSeconds(67), ClientPolicy.from(loaded)?.eventAccessTtl)
    }

    @Test
    fun rejectsMissingOrOrphanPolicyBeforeChangingClients() {
        val before = checkNotNull(clients.findByClientId("client-123"))
        for (policies in listOf(emptyMap(), custom.clients + ("orphan" to ClientPolicyConfig(setOf("backend-api"))))) {
            assertFailsWith<IllegalArgumentException> { synchronizer.synchronize(standard.client, policies) }
            assertEquals(before, clients.findByClientId("client-123"))
        }
        assertFailsWith<IllegalArgumentException> {
            synchronizer.synchronize(standard.client + ("missing-policy" to registration("missing-policy-client")), custom.clients)
        }
        assertNull(clients.findByClientId("missing-policy-client"))
    }

    @Test
    fun rejectsInvalidAudienceTtlAndTransitionsWithoutChangingClients() {
        val before = checkNotNull(clients.findByClientId("client-123"))
        val policy = custom.clients.getValue("client-123")
        val invalid = listOf(
            policy.copy(allowedAudiences = emptySet()),
            policy.copy(allowedAudiences = setOf(" ")),
            policy.copy(tenantAccessTtl = Duration.ZERO),
            policy.copy(eventAccessTtl = Duration.ofSeconds(-1)),
            policy.copy(eventAccessTtl = Duration.ofMillis(1500)),
            policy.copy(allowedTokenExchangeTransitions = setOf("event_access:event_access")),
        )
        for (config in invalid) {
            assertFailsWith<IllegalArgumentException> {
                synchronizer.synchronize(standard.client, custom.clients + ("client-123" to config))
            }
            assertEquals(before, clients.findByClientId("client-123"))
        }
    }

    @Test
    fun publicClientCannotEnableTokenExchangeOrIntrospectionOrMixAuthenticationMethods() {
        val public = registration("public-client").apply {
            registration.clientSecret = null
            registration.clientAuthenticationMethods = linkedSetOf("none")
            registration.authorizationGrantTypes = linkedSetOf("authorization_code")
            isRequireProofKey = true
        }
        val policy = ClientPolicyConfig(setOf("backend-api"))
        synchronizer.synchronize(standard.client + ("public" to public), custom.clients + ("public" to policy))
        assertEquals(ClientType.PUBLIC, ClientPolicy.from(checkNotNull(clients.findByClientId("public-client")))?.clientType)
        public.registration.authorizationGrantTypes.add("urn:ietf:params:oauth:grant-type:token-exchange")
        assertFailsWith<IllegalArgumentException> {
            synchronizer.synchronize(standard.client + ("public" to public), custom.clients + ("public" to policy))
        }
        public.registration.authorizationGrantTypes.remove("urn:ietf:params:oauth:grant-type:token-exchange")
        assertFailsWith<IllegalArgumentException> {
            synchronizer.synchronize(
                standard.client + ("public" to public),
                custom.clients + ("public" to policy.copy(tokenIntrospectionAllowed = true)),
            )
        }
        public.registration.clientSecret = "dummy-secret"
        public.registration.clientAuthenticationMethods.add("client_secret_basic")
        assertFailsWith<IllegalArgumentException> {
            synchronizer.synchronize(standard.client + ("public" to public), custom.clients + ("public" to policy))
        }
        assertNotNull(clients.findByClientId("client-123"))
    }

    @Test
    fun rejectsExchangeTransitionsWithoutGrantAndOpaqueAccessTokenFormat() {
        val registration = registration("invalid-client")
        assertFailsWith<IllegalArgumentException> {
            synchronizer.synchronize(
                standard.client + ("invalid" to registration),
                custom.clients + ("invalid" to ClientPolicyConfig(setOf("backend-api"), setOf("tenant_access:event_access"))),
            )
        }
        registration.token.accessTokenFormat = "reference"
        assertFailsWith<IllegalArgumentException> {
            synchronizer.synchronize(standard.client + ("invalid" to registration), custom.clients + ("invalid" to ClientPolicyConfig(setOf("backend-api"))))
        }
        assertNull(clients.findByClientId("invalid-client"))
    }

    private fun registration(clientId: String): OAuth2AuthorizationServerProperties.Client =
        OAuth2AuthorizationServerProperties.Client().apply {
            registration.clientId = clientId
            registration.clientSecret = "dummy-secret"
            registration.clientAuthenticationMethods = linkedSetOf("client_secret_basic")
            registration.authorizationGrantTypes = linkedSetOf("authorization_code")
            registration.redirectUris = linkedSetOf("https://example.invalid/callback")
            registration.scopes = linkedSetOf("openid", "tenant.read")
        }
}
