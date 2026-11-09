package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.IdpScopes
import dev.usbharu.toloidp.user.UserAccountRules
import dev.usbharu.toloidp.user.UserAlreadyExistsException
import dev.usbharu.toloidp.user.UserRegistrationService
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
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
    private val registration: UserRegistrationService,
    private val resourceParser: ResourceParser,
    private val challenges: LoginChallenges,
    private val registeredClientRepository: RegisteredClientRepository,
    private val clock: Clock,
    transactionManager: PlatformTransactionManager,
) {
    private val registrationTransaction = TransactionTemplate(transactionManager)

    @PostMapping("/signup")
    fun signup(
        @RequestBody request: SignupRequest,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<LoginResponse> {
        val tenantId = challenges.tenant(request.challenge)
            ?.takeIf { challenges.registration(request.challenge) }
            ?: reject(HttpStatus.BAD_REQUEST, "Invalid login challenge", null, "login_challenge_invalid")
        val clientId = challenges.clientId(request.challenge)
            ?: reject(HttpStatus.BAD_REQUEST, "Invalid login challenge", tenantId, "login_challenge_invalid")
        val client = registeredClientRepository.findByClientId(clientId)
            ?: reject(HttpStatus.BAD_REQUEST, "Invalid login challenge", tenantId, "login_challenge_invalid")
        if (IdpScopes.TENANT_JOIN !in client.scopes) {
            reject(HttpStatus.BAD_REQUEST, "Invalid login challenge", tenantId, "client_not_allowed")
        }
        if (!UserAccountRules.isValidUsername(request.username)) {
            reject(HttpStatus.BAD_REQUEST, "Invalid username", tenantId, "username_invalid")
        }
        if (!UserAccountRules.isValidPassword(request.password)) {
            reject(HttpStatus.BAD_REQUEST, "Invalid password", tenantId, "password_invalid")
        }
        val loginId = UUID.randomUUID().toString()
        val user = try {
            registrationTransaction.execute {
                val created = registration.create(tenantId, request.username, request.password)
                if (!challenges.authenticate(request.challenge, loginId, created.id)) {
                    reject(HttpStatus.BAD_REQUEST, "Invalid login challenge", tenantId, "login_challenge_invalid")
                }
                created
            }!!
        } catch (_: UserAlreadyExistsException) {
            reject(HttpStatus.CONFLICT, "Username is already registered", tenantId, "username_taken")
        }
        log.structuredInfo(
            "User registered",
            "event" to "user_registered",
            "subject" to user.id,
            "tenant_id" to tenantId,
        )
        establishLoginSession(httpRequest, user, loginId, clock)
        log.structuredInfo(
            "Signup completed",
            "event" to "signup_completed",
            "subject" to user.id,
            "tenant_id" to tenantId,
            "result" to "success",
        )
        return ResponseEntity.status(HttpStatus.CREATED).body(
            LoginResponse(
                sub = user.id,
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
    }
}

data class SignupRequest(
    val username: String,
    val password: String,
    val challenge: String,
)
