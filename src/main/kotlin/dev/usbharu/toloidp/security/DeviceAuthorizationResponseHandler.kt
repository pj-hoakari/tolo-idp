package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.http.converter.OAuth2DeviceAuthorizationResponseHttpMessageConverter
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.web.util.UriComponentsBuilder

/**
 * Writes the RFC 8628 device authorization response with the polling interval that
 * Spring Authorization Server's default endpoint filter leaves unset.
 */
class DeviceAuthorizationResponseHandler(
    private val verificationUri: String,
) : AuthenticationSuccessHandler {
    private val converter: HttpMessageConverter<OAuth2DeviceAuthorizationResponse> =
        OAuth2DeviceAuthorizationResponseHttpMessageConverter()

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val token = authentication as OAuth2DeviceAuthorizationRequestAuthenticationToken
        val verificationUriComplete = UriComponentsBuilder.fromUriString(verificationUri)
            .queryParam(OAuth2ParameterNames.USER_CODE, token.userCode.tokenValue)
            .build()
            .toUriString()
        val deviceAuthorizationResponse = OAuth2DeviceAuthorizationResponse.with(token.deviceCode, token.userCode)
            .verificationUri(verificationUri)
            .verificationUriComplete(verificationUriComplete)
            .interval(POLLING_INTERVAL_SECONDS)
            .build()
        converter.write(deviceAuthorizationResponse, null, ServletServerHttpResponse(response))
    }

    private companion object {
        const val POLLING_INTERVAL_SECONDS = 5L
    }
}
