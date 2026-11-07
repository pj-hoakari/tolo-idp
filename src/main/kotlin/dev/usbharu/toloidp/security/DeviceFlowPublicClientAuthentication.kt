package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.web.authentication.AuthenticationConverter

/**
 * Authenticates a public client that uses the Device Authorization Grant with only
 * `client_id` (RFC 8628). The standard SAS public-client converter only handles PKCE
 * authorization-code requests.
 */
class DeviceFlowPublicClientAuthenticationConverter(
    private val deviceAuthorizationEndpoint: String,
    private val tokenEndpoint: String,
) : AuthenticationConverter {
    override fun convert(request: HttpServletRequest): Authentication? {
        if (request.method != "POST") return null
        val isDeviceAuthorization = request.requestURI.endsWith(deviceAuthorizationEndpoint)
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)
        val isPublicTokenRequest =
            request.requestURI.endsWith(tokenEndpoint) &&
                (grantType == AuthorizationGrantType.DEVICE_CODE.value ||
                    grantType == AuthorizationGrantType.REFRESH_TOKEN.value)
        if (!isDeviceAuthorization && !isPublicTokenRequest) return null
        if (request.getParameter(OAuth2ParameterNames.CLIENT_SECRET) != null) return null

        val clientIds = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID) ?: return null
        if (clientIds.size != 1 || clientIds[0].isBlank()) {
            throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST))
        }
        return OAuth2ClientAuthenticationToken(
            clientIds[0],
            ClientAuthenticationMethod.NONE,
            null,
            mapOf(DEVICE_FLOW_PUBLIC_CLIENT_MARKER to DeviceFlowPublicClientMarker),
        )
    }
}

private object DeviceFlowPublicClientMarker

private const val DEVICE_FLOW_PUBLIC_CLIENT_MARKER = "tolo-idp.device-flow-public-client"

class DeviceFlowPublicClientAuthenticationProvider(
    private val registeredClientRepository: RegisteredClientRepository,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication? {
        val clientAuthentication = authentication as OAuth2ClientAuthenticationToken
        if (clientAuthentication.clientAuthenticationMethod != ClientAuthenticationMethod.NONE) {
            return null
        }
        if (clientAuthentication.additionalParameters[DEVICE_FLOW_PUBLIC_CLIENT_MARKER] !== DeviceFlowPublicClientMarker) {
            return null
        }
        val clientId = clientAuthentication.principal?.toString()?.takeIf { it.isNotBlank() }
            ?: throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT))
        val registeredClient = registeredClientRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT))
        if (ClientAuthenticationMethod.NONE !in registeredClient.clientAuthenticationMethods) {
            throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT))
        }
        return OAuth2ClientAuthenticationToken(
            registeredClient,
            ClientAuthenticationMethod.NONE,
            null,
        )
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication)
}
