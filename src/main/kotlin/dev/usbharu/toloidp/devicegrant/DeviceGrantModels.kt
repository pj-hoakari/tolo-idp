package dev.usbharu.toloidp.devicegrant

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
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

data class EdgeDeviceRevocation(
    val eventId: String,
    val edgeDeviceId: String,
    val revokedAt: Instant,
    val permanent: Boolean,
)

sealed interface DeviceGrantRefreshOutcome {
    data class Issued(
        val authentication: OAuth2AccessTokenAuthenticationToken,
    ) : DeviceGrantRefreshOutcome

    data object Rejected : DeviceGrantRefreshOutcome
}

/**
 * Carries the grant that must be failed closed when refresh state cannot be persisted.
 *
 * The provider revokes this grant in a new transaction after the failed refresh transaction
 * has rolled back, so the presented refresh token cannot remain usable.
 */
class DeviceGrantRefreshStateException(
    val grant: DeviceGrant,
    cause: Throwable,
) : RuntimeException("device_grant_refresh_state_failed", cause)

class BffAuthenticationException : RuntimeException("bff_client_authentication_failed")

class StaffTokenInvalidException : RuntimeException("staff_token_invalid")

class StaffNotAuthorizedException : RuntimeException("staff_not_authorized")

class DeviceGrantRejectedException(
    val reason: String,
) : RuntimeException(reason)
