package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.user.IdpUserDetails
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import java.time.Clock

fun establishLoginSession(httpRequest: HttpServletRequest, user: IdpUserDetails, loginId: String, clock: Clock) {
    val authentication = UsernamePasswordAuthenticationToken.authenticated(
        user.id,
        null,
        user.authorities + FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY),
    )
    authentication.details = linkedMapOf(
        OidcAuthenticationRequestValidator.AUTH_TIME to clock.instant().epochSecond.toString(),
        OidcAuthenticationRequestValidator.LOGIN_ID to loginId,
    )
    val context = SecurityContextImpl(authentication)
    SecurityContextHolder.setContext(context)
    val session = httpRequest.getSession(true)
    if (httpRequest.isRequestedSessionIdValid) {
        httpRequest.changeSessionId()
    }
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context)
}
