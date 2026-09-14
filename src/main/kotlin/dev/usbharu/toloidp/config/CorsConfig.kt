package dev.usbharu.toloidp.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class CorsConfig {
    @Bean
    fun corsConfigurationSource(properties: IdpProperties): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        val effectiveOrigins = effectiveAllowedOrigins(properties)
        if (effectiveOrigins.isEmpty()) {
            return source
        }

        val configuration = CorsConfiguration().apply {
            allowedOrigins = effectiveOrigins.toList()
            allowedMethods = listOf("GET", "POST", "OPTIONS")
            allowedHeaders = listOf("*")
            allowCredentials = true
        }
        source.registerCorsConfiguration("/api/login", configuration)
        source.registerCorsConfiguration("/api/logout", configuration)
        return source
    }

    private fun effectiveAllowedOrigins(properties: IdpProperties): Set<String> {
        val origins = properties.cors.allowedOrigins.toMutableSet()
        if (properties.jwk.allowEphemeral || properties.seed.enabled) {
            origins += DEV_TEST_ORIGINS
        }
        return origins
    }

    private companion object {
        val DEV_TEST_ORIGINS = setOf(
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        )
    }
}
