package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.devicegrant.DeviceGrantService
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationToken

/** Delegates the camera's complete initial exchange to a Spring-managed transaction. */
open class SpecDeviceCodeAuthenticationProvider(
    private val delegate: OAuth2DeviceCodeAuthenticationProvider,
    private val deviceGrantService: DeviceGrantService,
    private val cameraClientId: String,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication? {
        val request = authentication as OAuth2DeviceCodeAuthenticationToken
        val client = (request.principal as? OAuth2ClientAuthenticationToken)?.registeredClient
        if (client?.clientId != cameraClientId) {
            return delegate.authenticate(authentication)
        }
        return try {
            deviceGrantService.exchangeDeviceCode(request.deviceCode) {
                delegate.authenticate(authentication) as OAuth2AccessTokenAuthenticationToken
            }
        } catch (ex: OAuth2AuthenticationException) {
            throw ex
        } catch (_: RuntimeException) {
            throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2DeviceCodeAuthenticationToken::class.java.isAssignableFrom(authentication)
}
