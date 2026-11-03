package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.devicegrant.DeviceGrantService
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken
import org.springframework.transaction.annotation.Transactional

/**
 * Refresh token provider with device-grant revocation, reuse detection and rotation
 * bookkeeping for the ESP camera client. Other clients use the standard SAS provider.
 */
open class SpecRefreshTokenAuthenticationProvider(
    private val delegate: OAuth2RefreshTokenAuthenticationProvider,
    private val authorizationService: OAuth2AuthorizationService,
    private val deviceGrantService: DeviceGrantService,
    private val cameraClientId: String,
) : AuthenticationProvider {
    @Transactional
    override fun authenticate(authentication: Authentication): Authentication {
        val refreshAuthentication = authentication as OAuth2RefreshTokenAuthenticationToken
        val client = (refreshAuthentication.principal as? OAuth2ClientAuthenticationToken)?.registeredClient
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_client"))
        if (client.clientId != cameraClientId) {
            return delegate.authenticate(authentication)
                ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        }

        val authorization = authorizationService.findByToken(
            refreshAuthentication.refreshToken,
            OAuth2TokenType.REFRESH_TOKEN,
        )
        if (authorization == null) {
            deviceGrantService.handleReusedRefreshToken(refreshAuthentication.refreshToken)
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
        val grant = deviceGrantService.findByAuthorizationId(authorization.id)
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        if (grant.clientId != cameraClientId || authorization.principalName != grant.approverSubject) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
        deviceGrantService.requireActiveGrant(authorization.id, cameraClientId)

        val result = delegate.authenticate(authentication) as? OAuth2AccessTokenAuthenticationToken
            ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        val newRefreshToken = result.refreshToken
            ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        deviceGrantService.rotateRefreshToken(grant, refreshAuthentication.refreshToken, newRefreshToken)
        return result
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2RefreshTokenAuthenticationToken::class.java.isAssignableFrom(authentication)
}
