package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationConverter

class AuthorizationRequestConverter : AuthenticationConverter {
    private val delegate = OAuth2AuthorizationCodeRequestAuthenticationConverter()

    override fun convert(request: HttpServletRequest): Authentication? {
        val converted = delegate.convert(request)
        if (converted !is OAuth2AuthorizationCodeRequestAuthenticationToken) {
            return converted
        }

        val additionalParameters = converted.additionalParameters.toMutableMap()
        if ("openid" in converted.scopes.orEmpty()) {
            // OIDC Request URI is unsupported. Keep it on the request-local context so
            // our validator can reject it after client/redirect validation, rather than
            // letting the framework interpret it as a pushed authorization request.
            additionalParameters.remove(OAuth2ParameterNames.REQUEST_URI)
        }
        return AuthorizationRequestToken(converted, additionalParameters, request)
    }
}

/** Request-local context only; it is never stored in an authorization or token. */
class AuthorizationRequestToken(
    original: OAuth2AuthorizationCodeRequestAuthenticationToken,
    parameters: Map<String, Any>,
    val httpRequest: HttpServletRequest,
) : OAuth2AuthorizationCodeRequestAuthenticationToken(
    original.authorizationUri, original.clientId, original.principal as Authentication,
    original.redirectUri, original.state, original.scopes, parameters,
)
