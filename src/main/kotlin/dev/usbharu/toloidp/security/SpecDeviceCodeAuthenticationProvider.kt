package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.devicegrant.DeviceGrantService
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationToken

/**
 * Device code grant provider that records the initial refresh token for reuse detection.
 *
 * The Spring Authorization Server provider remains responsible for the RFC 8628 error
 * behaviour and for issuing tokens. Device grants only add the refresh-token history used
 * to revoke a grant when an old token is presented again.
 *
 * This provider is created manually in [dev.usbharu.toloidp.config.SecurityConfig], so the
 * transaction boundary is declared on [DeviceGrantService.recordIssuedRefreshToken] instead.
 */
open class SpecDeviceCodeAuthenticationProvider(
    private val delegate: OAuth2DeviceCodeAuthenticationProvider,
    private val authorizationService: OAuth2AuthorizationService,
    private val deviceGrantService: DeviceGrantService,
    private val cameraClientId: String,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val result = delegate.authenticate(authentication) as OAuth2AccessTokenAuthenticationToken
        if (result.registeredClient.clientId != cameraClientId) {
            return result
        }
        val refreshToken = result.refreshToken
            ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        val authorization = authorizationService.findByToken(refreshToken.tokenValue, OAuth2TokenType.REFRESH_TOKEN)
            ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        deviceGrantService.recordIssuedRefreshToken(authorization.id, refreshToken)
        return result
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2DeviceCodeAuthenticationToken::class.java.isAssignableFrom(authentication)
}
