package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.dao.DuplicateKeyException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException
import java.time.Clock
import java.util.UUID

@RestController
@RequestMapping("/api")
class SignupController(
    private val users: IdpUserDetailsManager,
    private val passwordEncoder: PasswordEncoder,
    private val resourceParser: ResourceParser,
    private val challenges: LoginChallenges,
    private val clock: Clock,
) {
    @PostMapping("/signup")
    fun signup(
        @RequestBody request: SignupRequest,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<LoginResponse> {
        val tenantId = challenges.tenant(request.challenge)
            ?.takeIf { challenges.registration(request.challenge) }
            ?: reject(HttpStatus.BAD_REQUEST, "Invalid login challenge", null, "login_challenge_invalid")
        if (!USERNAME.matches(request.username)) {
            reject(HttpStatus.BAD_REQUEST, "Invalid username", tenantId, "username_invalid")
        }
        if (request.password.length < MIN_PASSWORD_LENGTH || request.password.toByteArray().size > MAX_PASSWORD_BYTES) {
            reject(HttpStatus.BAD_REQUEST, "Invalid password", tenantId, "password_invalid")
        }
        val id = UUID.randomUUID().toString()
        try {
            if (users.userExists(tenantId, request.username)) throw DuplicateKeyException(request.username)
            users.createUser(
                tenantId,
                User.withUsername(request.username).password(passwordEncoder.encode(request.password)).roles("USER").build(),
                id,
            )
        } catch (_: DuplicateKeyException) {
            reject(HttpStatus.CONFLICT, "Username is already registered", tenantId, "username_taken")
        }
        val user = users.loadUserById(id)
        log.structuredInfo(
            "User registered",
            "event" to "user_registered",
            "subject" to id,
            "tenant_id" to tenantId,
        )
        val loginId = UUID.randomUUID().toString()
        if (!challenges.authenticate(request.challenge, loginId, id)) {
            reject(HttpStatus.BAD_REQUEST, "Invalid login challenge", tenantId, "login_challenge_invalid")
        }
        establishLoginSession(httpRequest, user, loginId, clock)
        log.structuredInfo(
            "Signup completed",
            "event" to "signup_completed",
            "subject" to id,
            "tenant_id" to tenantId,
            "result" to "success",
        )
        return ResponseEntity.status(HttpStatus.CREATED).body(
            LoginResponse(
                sub = id,
                username = user.username,
                tenantId = tenantId,
                resource = resourceParser.tenantResource(tenantId),
                authorities = user.authorities.mapNotNull { it.authority },
            ),
        )
    }

    private fun reject(status: HttpStatus, reason: String, tenantId: String?, failure: String): Nothing {
        log.structuredWarn(
            "Signup rejected",
            "event" to "signup_rejected",
            "tenant_id" to tenantId,
            "failure_reason" to failure,
        )
        throw ResponseStatusException(status, reason)
    }

    companion object {
        private val log = LoggerFactory.getLogger(SignupController::class.java)
        private val USERNAME = Regex("^[^\\s\\p{Cntrl}]{1,50}$")
        private const val MIN_PASSWORD_LENGTH = 8
        private const val MAX_PASSWORD_BYTES = 72
    }
}

data class SignupRequest(
    val username: String,
    val password: String,
    val challenge: String,
)
