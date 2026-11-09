package dev.usbharu.toloidp.user

import java.nio.charset.StandardCharsets
import java.util.UUID

/** Rules shared by the user creation API and development seed users. */
object UserAccountRules {
    val TENANT_ID = Regex("^[A-Za-z0-9_-]{1,64}$")
    val USERNAME = Regex("^[^\\s\\p{Cntrl}]{1,50}$")
    const val MIN_PASSWORD_LENGTH = 8
    const val MAX_PASSWORD_BYTES = 72

    fun isValidTenantId(value: String): Boolean = TENANT_ID.matches(value)

    fun isValidUsername(value: String): Boolean = USERNAME.matches(value)

    fun isValidPassword(value: String): Boolean =
        value.length >= MIN_PASSWORD_LENGTH &&
            value.toByteArray(StandardCharsets.UTF_8).size <= MAX_PASSWORD_BYTES

    fun isValidUserId(value: String): Boolean =
        runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)
}
