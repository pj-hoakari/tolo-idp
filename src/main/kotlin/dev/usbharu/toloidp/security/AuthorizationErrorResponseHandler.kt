package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
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
                val parameters = (exception.request as? AuthorizationRequestToken)?.httpRequest?.parameterMap ?: request.parameterMap
                val challenge = challenges.issue(exception.request.clientId, exception.tenantId, parameters)
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

    private fun sendClientError(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: OAuth2AuthorizationCodeRequestAuthenticationException,
    ) {
        val error = exception.error
        val authorization = exception.authorizationCodeRequestAuthentication
        val redirectUri = authorization?.redirectUri
        if (authorization == null || redirectUri.isNullOrEmpty()) {
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

private const val INVALID_CHALLENGE = "invalid_challenge"
