package dev.usbharu.toloidp.devicegrant

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.config.IdpProperties
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Component
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * HTTP Basic authentication for the BFF-only device authorization endpoints.
 *
 * These endpoints are called server-to-server without an IdP login session, so they use
 * the registered confidential BFF client credentials instead of user sessions.
 */
@Component
class BffClientAuthenticator(
    private val registeredClientRepository: RegisteredClientRepository,
    private val passwordEncoder: PasswordEncoder,
    private val properties: IdpProperties,
) {
    fun authenticate(authorizationHeader: String?): RegisteredClient {
        val credentials = parseBasicCredentials(authorizationHeader)
        val client = registeredClientRepository.findByClientId(credentials.clientId)
            ?: throw BffAuthenticationException()
        if (client.clientId != properties.deviceAuthorization.bffClientId) {
            throw BffAuthenticationException()
        }
        val policy = ClientPolicy.from(client) ?: throw BffAuthenticationException()
        if (policy.clientType != ClientType.CONFIDENTIAL ||
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC !in client.clientAuthenticationMethods
        ) {
            throw BffAuthenticationException()
        }
        val encodedSecret = client.clientSecret ?: throw BffAuthenticationException()
        if (!passwordEncoder.matches(credentials.clientSecret, encodedSecret)) {
            throw BffAuthenticationException()
        }
        return client
    }

    private fun parseBasicCredentials(header: String?): BasicCredentials {
        if (header == null) throw BffAuthenticationException()
        val parts = header.trim().split(Regex("\\s+"), limit = 2)
        if (parts.size != 2 || !parts[0].equals("Basic", ignoreCase = true)) {
            throw BffAuthenticationException()
        }
        val decoded = try {
            Base64.getDecoder().decode(parts[1])
        } catch (_: IllegalArgumentException) {
            throw BffAuthenticationException()
        }
        val value = String(decoded, StandardCharsets.UTF_8)
        val separator = value.indexOf(':')
        if (separator <= 0 || separator == value.lastIndex) throw BffAuthenticationException()
        val clientId = decode(value.substring(0, separator))
        val clientSecret = decode(value.substring(separator + 1))
        if (clientId.isBlank() || clientSecret.isBlank()) throw BffAuthenticationException()
        return BasicCredentials(clientId, clientSecret)
    }

    private fun decode(value: String): String =
        try {
            URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        } catch (_: IllegalArgumentException) {
            throw BffAuthenticationException()
        }

    private data class BasicCredentials(
        val clientId: String,
        val clientSecret: String,
    )
}
