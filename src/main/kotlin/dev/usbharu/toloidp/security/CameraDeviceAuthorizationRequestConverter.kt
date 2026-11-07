package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceAuthorizationRequestAuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationConverter

/**
 * Rejects camera-supplied event and edge device identifiers.
 *
 * The device authorization request only carries the client and scope. Event and device
 * binding is established by the BFF approval, never by the camera.
 */
class CameraDeviceAuthorizationRequestConverter : AuthenticationConverter {
    private val delegate = OAuth2DeviceAuthorizationRequestAuthenticationConverter()

    override fun convert(request: HttpServletRequest): Authentication? {
        if (request.getParameterValues(EDGE_DEVICE_ID_PARAMETER) != null ||
            request.getParameterValues(EVENT_ID_PARAMETER) != null
        ) {
            throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST))
        }
        return delegate.convert(request)
    }

    private companion object {
        const val EVENT_ID_PARAMETER = "event_id"
    }
}
