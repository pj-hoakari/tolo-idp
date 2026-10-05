package dev.usbharu.toloidp.client

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertNull

@SpringBootTest(
    properties = [
        "tolo-idp.seed.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:client-policy-tests;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;DATABASE_TO_UPPER=false",
    ],
)
class ClientPolicyRepositoryTests(
    @Autowired private val repository: ClientPolicyRepository,
) {
    @BeforeEach
    fun setUp() {
        repository.deleteAll()
    }

    @Test
    fun mapsClientPolicyCsvValuesAndTtls() {
        repository.save(
            ClientPolicy(
                clientId = "client-a",
                clientType = ClientType.CONFIDENTIAL,
                allowedGrantTypes = setOf("authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"),
                allowedTransitions = setOf("tenant_access:event_access"),
                allowedAudiences = setOf("backend-api", "events-api"),
                allowedScopes = setOf("tenant.read", "events.read", "events.manage"),
                tenantAccessTtl = Duration.ofSeconds(900),
                eventAccessTtl = Duration.ofSeconds(600),
            ),
        )

        val policy = repository.findByClientId("client-a")

        assertEquals(
            ClientPolicy(
                clientId = "client-a",
                clientType = ClientType.CONFIDENTIAL,
                allowedGrantTypes = setOf("authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"),
                allowedTransitions = setOf("tenant_access:event_access"),
                allowedAudiences = setOf("backend-api", "events-api"),
                allowedScopes = setOf("tenant.read", "events.read", "events.manage"),
                tenantAccessTtl = Duration.ofSeconds(900),
                eventAccessTtl = Duration.ofSeconds(600),
            ),
            policy,
        )
    }

    @Test
    fun mapsEmptyCsvColumnsToEmptySets() {
        repository.save(
            ClientPolicy(
                clientId = "client-public",
                clientType = ClientType.PUBLIC,
                allowedGrantTypes = emptySet(),
                allowedTransitions = emptySet(),
                allowedAudiences = emptySet(),
                allowedScopes = emptySet(),
                tenantAccessTtl = Duration.ofSeconds(1),
                eventAccessTtl = Duration.ofSeconds(2),
            ),
        )

        val policy = repository.findByClientId("client-public")

        assertEquals(ClientType.PUBLIC, policy?.clientType)
        assertEquals(emptySet(), policy?.allowedGrantTypes)
        assertEquals(emptySet(), policy?.allowedTransitions)
        assertEquals(emptySet(), policy?.allowedAudiences)
        assertEquals(emptySet(), policy?.allowedScopes)
        assertEquals(Duration.ofSeconds(1), policy?.tenantAccessTtl)
        assertEquals(Duration.ofSeconds(2), policy?.eventAccessTtl)
    }

    @Test
    fun returnsNullForUnknownClient() {
        assertNull(repository.findByClientId("missing-client"))
    }
}
