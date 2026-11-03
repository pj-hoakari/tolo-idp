package dev.usbharu.toloidp.devicegrant

import com.fasterxml.jackson.annotation.JsonProperty
import dev.usbharu.toloidp.security.STAFF_TOKEN_HEADER
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/device-authorization")
class DeviceAuthorizationController(
    private val bffClientAuthenticator: BffClientAuthenticator,
    private val deviceGrantService: DeviceGrantService,
) {
    @PostMapping("/approve")
    fun approve(
        @RequestHeader(HttpHeaders.AUTHORIZATION, required = false) authorization: String?,
        @RequestHeader(STAFF_TOKEN_HEADER, required = false) staffToken: String?,
        @RequestBody request: DeviceAuthorizationApprovalRequest,
    ): ResponseEntity<DeviceAuthorizationApprovalResponse> {
        val bffClient = try {
            bffClientAuthenticator.authenticate(authorization)
        } catch (_: BffAuthenticationException) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        }
        return try {
            val grant = deviceGrantService.approve(
                userCode = request.userCode,
                eventId = request.eventId,
                edgeDeviceId = request.edgeDeviceId,
                staffToken = staffToken,
                bffClient = bffClient,
            )
            ResponseEntity.ok(
                DeviceAuthorizationApprovalResponse(
                    grantId = grant.id,
                    eventId = grant.eventId,
                    edgeDeviceId = grant.edgeDeviceId,
                    approvedAt = grant.approvedAt,
                    expiresAt = grant.absoluteExpiresAt,
                ),
            )
        } catch (_: StaffTokenInvalidException) {
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        } catch (_: StaffNotAuthorizedException) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).build()
        } catch (_: DeviceGrantRejectedException) {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build()
        }
    }

    @PostMapping("/revoke")
    fun revoke(
        @RequestHeader(HttpHeaders.AUTHORIZATION, required = false) authorization: String?,
        @RequestBody request: DeviceAuthorizationRevocationRequest,
    ): ResponseEntity<Void> {
        try {
            bffClientAuthenticator.authenticate(authorization)
        } catch (_: BffAuthenticationException) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        }
        return try {
            deviceGrantService.revoke(request.eventId, request.edgeDeviceId)
            ResponseEntity.noContent().build()
        } catch (_: DeviceGrantRejectedException) {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build()
        }
    }
}

data class DeviceAuthorizationApprovalRequest(
    @JsonProperty("user_code")
    val userCode: String = "",
    @JsonProperty("event_id")
    val eventId: String = "",
    @JsonProperty("edge_device_id")
    val edgeDeviceId: String = "",
)

data class DeviceAuthorizationApprovalResponse(
    @JsonProperty("grant_id")
    val grantId: String,
    @JsonProperty("event_id")
    val eventId: String,
    @JsonProperty("edge_device_id")
    val edgeDeviceId: String,
    @JsonProperty("approved_at")
    val approvedAt: java.time.Instant,
    @JsonProperty("expires_at")
    val expiresAt: java.time.Instant,
)

data class DeviceAuthorizationRevocationRequest(
    @JsonProperty("event_id")
    val eventId: String = "",
    @JsonProperty("edge_device_id")
    val edgeDeviceId: String = "",
)
