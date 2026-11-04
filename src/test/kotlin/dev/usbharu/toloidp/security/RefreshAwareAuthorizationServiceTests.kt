package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import java.time.Instant
import java.util.UUID
import kotlin.test.assertFailsWith

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:refresh-aware;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
class RefreshAwareAuthorizationServiceTests(
    @Autowired private val authorizationService: OAuth2AuthorizationService,
    @Autowired private val registeredClientRepository: RegisteredClientRepository,
) {
    @Test
    fun aNormalSaveIsRejectedAfterRefreshRevocationAndAccessRevocationStillSucceeds() {
        val client = registeredClientRepository.findByClientId("client-123")!!
        val now = Instant.now()
        val access = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "access-token",
            now,
            now.plusSeconds(300),
            setOf("openid"),
        )
        val refresh = OAuth2RefreshToken("refresh-token", now, now.plusSeconds(3600))
        val authorization = OAuth2Authorization.withRegisteredClient(client)
            .id(UUID.randomUUID().toString())
            .principalName("user-123")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(setOf("openid"))
            .token(access)
            .token(refresh)
            .build()
        val service = authorizationService as RefreshRevocationAware

        authorizationService.save(authorization)
        service.saveRefreshRevocation(authorization)
        service.saveAccessRevocation(authorization)

        assertFailsWith<OAuth2AuthenticationException> {
            authorizationService.save(OAuth2Authorization.from(authorization).build())
        }
    }
}
