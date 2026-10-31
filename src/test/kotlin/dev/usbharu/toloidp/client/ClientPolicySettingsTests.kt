package dev.usbharu.toloidp.client

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.Duration
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull

@SpringBootTest(
    properties = [
        "spring.datasource.url=jdbc:h2:mem:client-policy-settings;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
    ],
)
class ClientPolicySettingsTests(
    @Autowired private val clients: RegisteredClientRepository,
    @Autowired private val jdbc: JdbcTemplate,
) {
    @Test
    fun savesAllPolicySettingsInRegisteredClientAndReadsThemBack() {
        val client = client()
        val policy = ClientPolicy(
            clientId = client.clientId,
            clientType = ClientType.CONFIDENTIAL,
            allowedGrantTypes = setOf(AuthorizationGrantType.CLIENT_CREDENTIALS.value),
            allowedTransitions = setOf("tenant_access:event_access"),
            allowedAudiences = setOf("backend-api", "events-api"),
            allowedScopes = setOf("tenant.read", "events.read"),
            tenantAccessTtl = Duration.ofSeconds(123),
            eventAccessTtl = Duration.ofSeconds(45),
            tokenIntrospectionAllowed = true,
        )
        clients.save(policy.toRegisteredClient(client))
        val loaded = checkNotNull(clients.findByClientId(client.clientId))
        assertEquals(policy, ClientPolicy.from(loaded))
        assertEquals(Duration.ofSeconds(123), loaded.tokenSettings.accessTokenTimeToLive)
        assertEquals(0, jdbc.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE LOWER(TABLE_NAME) = 'idp_client_policy'",
            Int::class.java,
        ))
    }

    @Test
    fun readsEmptyPermissionListsWithoutGrantingAnything() {
        val client = client()
        val policy = ClientPolicy(
            client.clientId, ClientType.CONFIDENTIAL, setOf("client_credentials"), emptySet(), emptySet(), emptySet(),
            Duration.ofSeconds(1), Duration.ofSeconds(2),
        )
        clients.save(policy.toRegisteredClient(client))
        assertEquals(policy, ClientPolicy.from(checkNotNull(clients.findByClientId(client.clientId))))
    }

    @Test
    fun missingOrMalformedPolicyFailsClosed() {
        val client = client()
        assertNull(ClientPolicy.from(client))
        val policy = ClientPolicy(
            client.clientId, ClientType.CONFIDENTIAL, setOf("client_credentials"), emptySet(), setOf("backend-api"), emptySet(),
            Duration.ofSeconds(1), Duration.ofSeconds(2),
        ).toRegisteredClient(client)
        for (badValue in listOf("45", -1L, 0L, 1.5)) {
            assertNull(ClientPolicy.from(RegisteredClient.from(policy).tokenSettings(
                TokenSettings.withSettings(policy.tokenSettings.settings).setting(ClientPolicy.EVENT_ACCESS_TTL_SECONDS, badValue).build(),
            ).build()))
        }
        assertNull(ClientPolicy.from(RegisteredClient.from(policy).clientSettings(
            ClientSettings.withSettings(policy.clientSettings.settings).setting(ClientPolicy.ALLOWED_AUDIENCES, listOf(1)).build(),
        ).build()))
        assertNull(ClientPolicy.from(RegisteredClient.from(policy).clientSettings(
            ClientSettings.withSettings(policy.clientSettings.settings).setting(ClientPolicy.TOKEN_INTROSPECTION_ALLOWED, "true").build(),
        ).build()))
        assertNull(ClientPolicy.from(RegisteredClient.from(policy).clientSettings(
            ClientSettings.withSettings(policy.clientSettings.settings).settings { it.remove(ClientPolicy.TOKEN_INTROSPECTION_ALLOWED) }.build(),
        ).build()))
    }

    private fun client(): RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-${UUID.randomUUID()}")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .build()
}
