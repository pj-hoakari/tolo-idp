package dev.usbharu.toloidp.config

import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.springframework.transaction.annotation.Transactional

@Configuration
class SeedDataConfig {
    @Bean
    fun seedDataRunner(
        properties: IdpProperties,
        passwordEncoder: PasswordEncoder,
        userDetailsManager: IdpUserDetailsManager,
    ): SeedDataRunner =
        SeedDataRunner(
            properties,
            passwordEncoder,
            userDetailsManager,
        )
}

open class SeedDataRunner(
    private val properties: IdpProperties,
    private val passwordEncoder: PasswordEncoder,
    private val userDetailsManager: IdpUserDetailsManager,
) : ApplicationRunner {
    @Transactional
    override fun run(args: ApplicationArguments) {
        seed()
    }

    private fun seed() {
        if (!properties.seed.enabled) {
            return
        }

        if (!userDetailsManager.userExists("tenant-a", "user-123")) {
            userDetailsManager.createUser(
                "tenant-a",
                User.withUsername("user-123")
                    .password(passwordEncoder.encode(properties.seed.userPassword))
                    .roles("USER")
                    .build(),
                IdpUserDetailsManager.DEVELOPMENT_USER_ID,
            )
        }
    }
}
