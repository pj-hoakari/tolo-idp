package dev.usbharu.toloidp.user

import org.springframework.dao.DuplicateKeyException
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

class UserAlreadyExistsException(message: String) : RuntimeException(message)

/**
 * Creates users with the same validation, password encoding and authorities as the signup API.
 * The development seed uses this service so a seeded user is equivalent to an API-created user.
 */
open class UserRegistrationService(
    private val users: IdpUserDetailsManager,
    private val passwordEncoder: PasswordEncoder,
) {
    @Transactional
    open fun create(
        tenantId: String,
        username: String,
        rawPassword: String,
        id: String = UUID.randomUUID().toString(),
    ): IdpUserDetails {
        require(UserAccountRules.isValidTenantId(tenantId)) { "Invalid tenantId" }
        require(UserAccountRules.isValidUsername(username)) { "Invalid username" }
        require(UserAccountRules.isValidPassword(rawPassword)) { "Invalid password" }
        require(UserAccountRules.isValidUserId(id)) { "id must be a canonical UUID" }
        if (users.userExists(tenantId, username)) {
            throw UserAlreadyExistsException("Username is already registered")
        }
        val user = User.withUsername(username)
            .password(passwordEncoder.encode(rawPassword))
            .roles("USER")
            .build()
        try {
            users.createUser(tenantId, user, id)
        } catch (ex: DuplicateKeyException) {
            throw UserAlreadyExistsException("Username or id is already registered")
        }
        return users.loadUserById(id)
    }
}
