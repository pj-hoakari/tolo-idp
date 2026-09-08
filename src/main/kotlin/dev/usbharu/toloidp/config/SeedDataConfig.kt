package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.provisioning.UserDetailsManager
import org.springframework.transaction.annotation.Transactional
import java.time.Duration
import java.util.UUID

@Configuration
class SeedDataConfig {
    @Bean
    fun seedDataRunner(
        properties: IdpProperties,
        passwordEncoder: PasswordEncoder,
        userDetailsManager: UserDetailsManager,
        registeredClientRepository: RegisteredClientRepository,
        clientPolicyRepository: ClientPolicyRepository,
    ): ApplicationRunner =
        SeedDataRunner(
            properties,
            passwordEncoder,
            userDetailsManager,
            registeredClientRepository,
            clientPolicyRepository,
        )
}

open class SeedDataRunner(
    private val properties: IdpProperties,
    private val passwordEncoder: PasswordEncoder,
    private val userDetailsManager: UserDetailsManager,
    private val registeredClientRepository: RegisteredClientRepository,
    private val clientPolicyRepository: ClientPolicyRepository,
) : ApplicationRunner {
    @Transactional
    override fun run(args: org.springframework.boot.ApplicationArguments) {
        seed()
    }

    private fun seed() {
        if (!properties.seed.enabled) {
            return
        }

        if (!userDetailsManager.userExists("user-123")) {
            userDetailsManager.createUser(
                User.withUsername("user-123")
                    .password(passwordEncoder.encode(properties.seed.userPassword))
                    .roles("USER")
                    .build(),
            )
        }

        if (registeredClientRepository.findByClientId("client-123") == null) {
            registeredClientRepository.save(
                RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("client-123")
                    .clientSecret(passwordEncoder.encode(properties.seed.clientSecret))
                    .clientName("Development confidential client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-123")
                    .scope("openid")
                    .scope("tenant.read")
                    .scope("tenant.write")
                    .scope("events.read")
                    .scope("events.write")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .tokenSettings(
                        TokenSettings.builder()
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                            .build(),
                    )
                    .build(),
            )
        }

        if (clientPolicyRepository.findByClientId("client-123") == null) {
            clientPolicyRepository.save(
                ClientPolicy(
                    clientId = "client-123",
                    clientType = ClientType.CONFIDENTIAL,
                    allowedGrantTypes = setOf(
                        AuthorizationGrantType.AUTHORIZATION_CODE.value,
                        AuthorizationGrantType.TOKEN_EXCHANGE.value,
                    ),
                    allowedTransitions = setOf("tenant_access:event_access"),
                    allowedAudiences = setOf("backend-api"),
                    allowedScopes = setOf("openid", "tenant.read", "tenant.write", "events.read", "events.write"),
                    tenantAccessTtl = Duration.ofSeconds(900),
                    eventAccessTtl = Duration.ofSeconds(600),
                ),
            )
        }
    }
}
