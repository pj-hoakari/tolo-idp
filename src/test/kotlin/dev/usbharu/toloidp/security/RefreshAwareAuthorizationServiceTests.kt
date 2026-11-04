package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import java.util.UUID
import kotlin.test.assertFailsWith

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:refresh-aware;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
class RefreshAwareAuthorizationServiceTests(
    @Autowired private val authorizationService: OAuth2AuthorizationService,
    @Autowired private val registeredClientRepository: RegisteredClientRepository,
) {
    @Test
    fun aNormalSaveIsRejectedAfterRefreshRevocation() {
        val client = registeredClientRepository.findByClientId("client-123")!!
        val authorization = OAuth2Authorization.withRegisteredClient(client)
            .id(UUID.randomUUID().toString())
            .principalName("user-123")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(setOf("openid"))
            .build()

        (authorizationService as RefreshRevocationAware).saveRefreshRevocation(authorization)

        assertFailsWith<OAuth2AuthenticationException> {
            authorizationService.save(OAuth2Authorization.from(authorization).build())
        }
    }
}
