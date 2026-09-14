package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.servlet.http.HttpSession
import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.resource.ResourceValidationException
import dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException

@RestController
@RequestMapping("/api")
class LoginController(
    private val userDetailsService: UserDetailsService,
    private val passwordEncoder: PasswordEncoder,
    private val relationService: RelationService,
    private val resourceParser: ResourceParser,
) {
    @PostMapping("/login")
    fun login(
        @RequestBody request: LoginRequest,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<LoginResponse> {
        log.structuredInfo(
            "Login started",
            "event" to "login_started",
            "username" to request.username,
            "tenant_id" to request.tenantId,
        )
        try {
            resourceParser.requireValidId(request.tenantId)
        } catch (ex: ResourceValidationException) {
            log.structuredWarn(
                "Login rejected",
                ex,
                "event" to "login_rejected",
                "username" to request.username,
                "tenant_id" to request.tenantId,
                "failure_reason" to "invalid_tenant_id",
            )
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid tenantId")
        }
        val user = try {
            userDetailsService.loadUserByUsername(request.username)
        } catch (ex: RuntimeException) {
            log.structuredWarn(
                "Login rejected",
                ex,
                "event" to "login_rejected",
                "username" to request.username,
                "tenant_id" to request.tenantId,
                "failure_reason" to "user_lookup_failed",
            )
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials")
        }
        if (!passwordEncoder.matches(request.password, user.password)) {
            log.structuredWarn(
                "Login rejected",
                "event" to "login_rejected",
                "username" to request.username,
                "tenant_id" to request.tenantId,
                "failure_reason" to "bad_credentials",
            )
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials")
        }
        try {
            relationService.getMembership(request.tenantId, user.username)
        } catch (ex: RelationLookupException) {
            log.structuredWarn(
                "Login rejected",
                ex,
                "event" to "login_rejected",
                "username" to user.username,
                "tenant_id" to request.tenantId,
                "failure_reason" to ex.reason,
            )
            throw ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant is not allowed")
        }
        val authentication = UsernamePasswordAuthenticationToken.authenticated(
            user.username,
            null,
            user.authorities + FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY),
        )
        val context = SecurityContextImpl(authentication)
        SecurityContextHolder.setContext(context)
        httpRequest.getSession(false)?.invalidate()
        val session = httpRequest.getSession(true)
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context)
        session.setAttribute(SELECTED_TENANT_SESSION_ATTRIBUTE, request.tenantId)
        log.structuredInfo(
            "Login completed",
            "event" to "login_completed",
            "username" to user.username,
            "tenant_id" to request.tenantId,
            "authority_count" to user.authorities.size,
            "result" to "success",
        )
        return ResponseEntity.ok(
            LoginResponse(
                username = user.username,
                tenantId = request.tenantId,
                resource = resourceParser.tenantResource(request.tenantId),
                authorities = user.authorities.mapNotNull { it.authority },
            ),
        )
    }

    @PostMapping("/logout")
    fun logout(
        session: HttpSession?,
        response: HttpServletResponse,
    ): ResponseEntity<Void> {
        log.structuredInfo(
            "Logout started",
            "event" to "logout_started",
            "session_present" to (session != null),
        )
        SecurityContextHolder.clearContext()
        session?.invalidate()
        response.status = HttpStatus.NO_CONTENT.value()
        log.structuredInfo(
            "Logout completed",
            "event" to "logout_completed",
            "session_invalidated" to (session != null),
            "result" to "success",
        )
        return ResponseEntity.noContent().build()
    }

    companion object {
        private val log = LoggerFactory.getLogger(LoginController::class.java)
    }
}

data class LoginRequest(
    val username: String,
    val password: String,
    val tenantId: String,
)

data class LoginResponse(
    val username: String,
    val tenantId: String,
    val resource: String,
    val authorities: List<String>,
)
