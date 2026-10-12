package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.scope.IdpScopes
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.provisioning.UserDetailsManager
import org.springframework.transaction.annotation.Transactional
import java.time.Duration

@Configuration
class SeedDataConfig {
    @Bean
    fun seedDataRunner(
        properties: IdpProperties,
        passwordEncoder: PasswordEncoder,
        userDetailsManager: UserDetailsManager,
        clientPolicyRepository: ClientPolicyRepository,
    ): ApplicationRunner =
        SeedDataRunner(
            properties,
            passwordEncoder,
            userDetailsManager,
            clientPolicyRepository,
        )
}

open class SeedDataRunner(
    private val properties: IdpProperties,
    private val passwordEncoder: PasswordEncoder,
    private val userDetailsManager: UserDetailsManager,
    private val clientPolicyRepository: ClientPolicyRepository,
) : ApplicationRunner {
    @Transactional
    override fun run(args: ApplicationArguments) {
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

        if (clientPolicyRepository.findByClientId(DEVELOPMENT_CLIENT_ID) == null) {
            clientPolicyRepository.save(
                ClientPolicy(
                    clientId = DEVELOPMENT_CLIENT_ID,
                    clientType = ClientType.CONFIDENTIAL,
                    allowedGrantTypes = setOf(
                        AuthorizationGrantType.AUTHORIZATION_CODE.value,
                        AuthorizationGrantType.TOKEN_EXCHANGE.value,
                    ),
                    allowedTransitions = setOf("tenant_access:event_access"),
                    allowedAudiences = setOf("backend-api"),
                    allowedScopes = IdpScopes.SUPPORTED,
                    tenantAccessTtl = Duration.ofSeconds(900),
                    eventAccessTtl = Duration.ofSeconds(600),
                ),
            )
        }
    }

    private companion object {
        const val DEVELOPMENT_CLIENT_ID = "client-123"
    }
}
