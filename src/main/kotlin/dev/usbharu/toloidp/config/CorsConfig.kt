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
        val configuration = CorsConfiguration().apply {
            allowedOrigins = listOf(properties.login.origin())
            allowedMethods = listOf("POST")
            allowedHeaders = listOf("content-type")
            allowCredentials = true
        }
        source.registerCorsConfiguration("/api/login", configuration)
        source.registerCorsConfiguration("/api/logout", configuration)
        return source
    }
}
