package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.RegistrationGrantType
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
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
        if (request.method == "POST" && !request.queryString.isNullOrBlank()) {
            // The framework's POST view excludes query parameters. Mixing a query
            // string into a form-post authorization request makes validation and
            // challenge storage disagree on scope, resource, and audience.
            throw OAuth2AuthorizationCodeRequestAuthenticationException(
                OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: request", null),
                null,
            )
        }
        val resumed = request.parameterMap.containsKey(LOGIN_CHALLENGE_PARAMETER)
        val authorizationRequest = if (resumed) resume(request) else request
        // Spring Security 7.1 stops parsing redirect_uri, scope, and state when
        // request_uri is present (RFC 9126 PAR semantics). This server rejects
        // request_uri in the OIDC validator, but the error response still needs the
        // original parameters to redirect to the registered client, so hide it from
        // the framework conversion and keep it on the request-local context.
        val converted = delegate.convert(authorizationRequest.withoutRequestUri())
        if (converted !is OAuth2AuthorizationCodeRequestAuthenticationToken) {
            return converted
        }

        val additionalParameters = converted.additionalParameters.toMutableMap()
        val registrationGrantParameters = RegistrationGrantType.entries
            .mapNotNull { type -> additionalParameters[type.parameter]?.let { type to it } }
            .toMap()
        return AuthorizationRequestToken(converted, additionalParameters, authorizationRequest, resumed, registrationGrantParameters)
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
    val registrationGrantParameters: Map<RegistrationGrantType, Any>,
) : OAuth2AuthorizationCodeRequestAuthenticationToken(
    original.authorizationUri, original.clientId, original.principal as Authentication,
    original.redirectUri, original.state, original.scopes, parameters,
) {
    private var grantedScopes: Set<String>? = null

    fun grantScopes(scopes: Set<String>) {
        grantedScopes = scopes
    }

    override fun getScopes(): Set<String> = grantedScopes ?: super.getScopes()
}

private class RequestUriStrippedRequest(request: HttpServletRequest) : HttpServletRequestWrapper(request) {
    override fun getParameter(name: String): String? =
        if (name == OAuth2ParameterNames.REQUEST_URI) null else super.getParameter(name)

    override fun getParameterValues(name: String): Array<String>? =
        if (name == OAuth2ParameterNames.REQUEST_URI) null else super.getParameterValues(name)

    override fun getParameterMap(): Map<String, Array<String>> =
        super.getParameterMap().filterKeys { it != OAuth2ParameterNames.REQUEST_URI }
}

private fun HttpServletRequest.withoutRequestUri(): HttpServletRequest =
    if (parameterMap.containsKey(OAuth2ParameterNames.REQUEST_URI)) RequestUriStrippedRequest(this) else this

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
