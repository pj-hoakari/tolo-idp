package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import dev.usbharu.toloidp.scope.ScopePolicy
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.web.util.UriComponentsBuilder
import org.springframework.web.util.UriUtils
import java.net.URI

class LoginChallengeRequiredException(
    val request: OAuth2AuthorizationCodeRequestAuthenticationToken,
    val tenantId: String,
) : OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error("login_required", "OAuth 2.0 Parameter: prompt", null), null)

class LoginChallengeRejectedException :
    OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error(INVALID_CHALLENGE), null)

class AuthorizationErrorResponseHandler(
    private val challenges: LoginChallenges,
    private val registeredClientRepository: RegisteredClientRepository,
    private val loginPage: URI,
    private val errorPage: URI,
) : AuthenticationFailureHandler {
    private val redirects = DefaultRedirectStrategy()

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ) {
        when (exception) {
            is LoginChallengeRequiredException -> {
                val parameters = challengeParameters(exception.request)
                val challenge = challenges.issue(
                    exception.request.clientId,
                    exception.tenantId,
                    parameters,
                    registration = exception.request.scopes == ScopePolicy.REGISTRATION_SCOPES,
                )
                val location = if (challenge == null) {
                    errorPage(OAuth2ErrorCodes.INVALID_REQUEST)
                } else {
                    UriComponentsBuilder.fromUri(loginPage).queryParam(LOGIN_CHALLENGE_PARAMETER, challenge).build().toUriString()
                }
                redirects.sendRedirect(request, response, location)
            }
            is LoginChallengeRejectedException -> redirects.sendRedirect(request, response, errorPage(INVALID_CHALLENGE))
            else -> sendClientError(request, response, exception as OAuth2AuthorizationCodeRequestAuthenticationException)
        }
    }

    private fun errorPage(error: String): String =
        UriComponentsBuilder.fromUri(errorPage).queryParam(OAuth2ParameterNames.ERROR, error).build().toUriString()

    private fun challengeParameters(token: OAuth2AuthorizationCodeRequestAuthenticationToken): Map<String, Array<String>> {
        val parameters = linkedMapOf<String, Array<String>>()
        parameters[OAuth2ParameterNames.RESPONSE_TYPE] = arrayOf("code")
        parameters[OAuth2ParameterNames.CLIENT_ID] = arrayOf(token.clientId)
        token.redirectUri?.takeIf { it.isNotBlank() }?.let {
            parameters[OAuth2ParameterNames.REDIRECT_URI] = arrayOf(it)
        }
        if (token.scopes.isNotEmpty()) {
            parameters[OAuth2ParameterNames.SCOPE] = arrayOf(token.scopes.joinToString(" "))
        }
        token.state?.takeIf { it.isNotBlank() }?.let {
            parameters[OAuth2ParameterNames.STATE] = arrayOf(it)
        }
        token.additionalParameters.forEach { (name, value) ->
            if (name !in STANDARD_PARAMETERS) {
                when (value) {
                    is String -> parameters[name] = arrayOf(value)
                    is Array<*> -> parameters[name] = value.filterIsInstance<String>().toTypedArray()
                    is Iterable<*> -> parameters[name] = value.filterIsInstance<String>().toTypedArray()
                }
            }
        }
        return parameters
    }

    private fun sendClientError(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: OAuth2AuthorizationCodeRequestAuthenticationException,
    ) {
        val error = exception.error
        val authorization = exception.authorizationCodeRequestAuthentication
        val redirectUri = authorization?.redirectUri
        val registeredClient = authorization?.clientId?.let(registeredClientRepository::findByClientId)
        if (authorization == null || redirectUri.isNullOrEmpty() ||
            registeredClient == null || redirectUri !in registeredClient.redirectUris
        ) {
            redirects.sendRedirect(request, response, errorPage(error.errorCode))
            return
        }
        val location = UriComponentsBuilder.fromUriString(redirectUri).queryParam(OAuth2ParameterNames.ERROR, error.errorCode)
        mapOf(
            OAuth2ParameterNames.ERROR_DESCRIPTION to error.description,
            OAuth2ParameterNames.ERROR_URI to error.uri,
            OAuth2ParameterNames.STATE to authorization.state,
        ).forEach { (name, value) ->
            if (!value.isNullOrEmpty()) location.queryParam(name, UriUtils.encode(value, Charsets.UTF_8))
        }
        redirects.sendRedirect(request, response, location.build(true).toUriString())
    }
}

private val STANDARD_PARAMETERS = setOf(
    OAuth2ParameterNames.RESPONSE_TYPE,
    OAuth2ParameterNames.CLIENT_ID,
    OAuth2ParameterNames.REDIRECT_URI,
    OAuth2ParameterNames.SCOPE,
    OAuth2ParameterNames.STATE,
)

private const val INVALID_CHALLENGE = "invalid_challenge"
