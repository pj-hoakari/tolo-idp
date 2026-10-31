package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationConverter
import java.net.URLEncoder
import java.util.Collections
import java.util.Enumeration

class AuthorizationRequestConverter(
    private val challenges: LoginChallenges,
) : AuthenticationConverter {
    private val delegate = OAuth2AuthorizationCodeRequestAuthenticationConverter()

    override fun convert(request: HttpServletRequest): Authentication? {
        val resumed = request.parameterMap.containsKey(LOGIN_CHALLENGE_PARAMETER)
        val authorizationRequest = if (resumed) resume(request) else request
        val converted = delegate.convert(authorizationRequest)
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
        return AuthorizationRequestToken(converted, additionalParameters, authorizationRequest, resumed)
    }

    private fun resume(request: HttpServletRequest): HttpServletRequest {
        val challenge = request.parameterMap.takeIf { request.method == "GET" && it.size == 1 }
            ?.get(LOGIN_CHALLENGE_PARAMETER)?.singleOrNull()
        val login = (SecurityContextHolder.getContext().authentication?.details as? Map<*, *>)
            ?.get(OidcAuthenticationRequestValidator.LOGIN_ID) as? String
        val stored = challenge?.let { challenges.consume(it, login) } ?: throw LoginChallengeRejectedException()
        return StoredAuthorizationRequest(request, stored)
    }
}

/** Request-local context only; it is never stored in an authorization or token. */
class AuthorizationRequestToken(
    original: OAuth2AuthorizationCodeRequestAuthenticationToken,
    parameters: Map<String, Any>,
    val httpRequest: HttpServletRequest,
    val resumed: Boolean,
) : OAuth2AuthorizationCodeRequestAuthenticationToken(
    original.authorizationUri, original.clientId, original.principal as Authentication,
    original.redirectUri, original.state, original.scopes, parameters,
)

private class StoredAuthorizationRequest(
    request: HttpServletRequest,
    stored: Map<String, List<String>>,
) : HttpServletRequestWrapper(request) {
    private val parameters = stored.mapValues { it.value.toTypedArray() }
    private val query = stored.flatMap { (name, values) -> values.map { "${encode(name)}=${encode(it)}" } }.joinToString("&")

    override fun getQueryString(): String = query

    override fun getParameter(name: String): String? = parameters[name]?.firstOrNull()

    override fun getParameterMap(): Map<String, Array<String>> = parameters

    override fun getParameterNames(): Enumeration<String> = Collections.enumeration(parameters.keys)

    override fun getParameterValues(name: String): Array<String>? = parameters[name]

    private fun encode(value: String): String = URLEncoder.encode(value, Charsets.UTF_8)
}
