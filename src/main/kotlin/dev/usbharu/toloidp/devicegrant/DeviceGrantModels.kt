package dev.usbharu.toloidp.devicegrant

import java.time.Instant

data class DeviceGrant(
    val id: String,
    val tenantId: String,
    val eventId: String,
    val edgeDeviceId: String,
    val approverSubject: String,
    val clientId: String,
    val approvedAt: Instant,
    val absoluteExpiresAt: Instant,
    val revokedAt: Instant? = null,
    val revokedReason: String? = null,
    val createdAt: Instant,
)

data class DeviceGrantRefreshToken(
    val tokenHash: String,
    val grantId: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val supersededAt: Instant? = null,
)

class BffAuthenticationException : RuntimeException("bff_client_authentication_failed")

class StaffTokenInvalidException : RuntimeException("staff_token_invalid")

class StaffNotAuthorizedException : RuntimeException("staff_not_authorized")

class DeviceGrantRejectedException(
    val reason: String,
) : RuntimeException(reason)
