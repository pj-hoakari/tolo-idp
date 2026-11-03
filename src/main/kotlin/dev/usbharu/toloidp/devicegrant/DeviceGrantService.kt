package dev.usbharu.toloidp.devicegrant

import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.security.DEVICE_GRANT_ID_ATTRIBUTE
import dev.usbharu.toloidp.security.JtiDenylistEntry
import dev.usbharu.toloidp.security.JtiDenylistRepository
import dev.usbharu.toloidp.security.TOKEN_USE_TENANT_ACCESS
import dev.usbharu.toloidp.security.TOKEN_USE_EVENT_ACCESS
import dev.usbharu.toloidp.scope.IdpScopes
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2DeviceCode
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2UserCode
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.Principal
import java.time.Clock
import java.time.Instant
import java.util.Locale

@Service
class DeviceGrantService(
    private val repository: DeviceGrantRepository,
    private val authorizationService: OAuth2AuthorizationService,
    private val registeredClientRepository: RegisteredClientRepository,
    private val users: IdpUserDetailsManager,
    private val relationService: RelationService,
    private val resourceParser: ResourceParser,
    private val jwtDecoder: JwtDecoder,
    private val jtiDenylistRepository: JtiDenylistRepository,
    private val auditService: AuditService,
    private val properties: IdpProperties,
    private val clock: Clock,
) {
    private val cameraClientId = properties.deviceAuthorization.cameraClientId
    private val grantMaxLifetime = properties.deviceAuthorization.grantMaxLifetime

    @Transactional
    fun approve(
        userCode: String,
        eventId: String,
        edgeDeviceId: String,
        staffToken: String?,
        bffClient: RegisteredClient,
    ): DeviceGrant {
        requireEventAndEdge(eventId, edgeDeviceId)
        val bffPolicy = ClientPolicy.from(bffClient) ?: throw BffAuthenticationException()
        val staff = verifyStaffToken(staffToken, bffPolicy.allowedAudiences)
        requireEventRole(staff.tenantId, staff.subject, eventId)

        repository.lockEdgeDevice(edgeDeviceId)
        if (repository.isRevoked(eventId, edgeDeviceId)) {
            reject("edge_device_revoked")
        }

        val authorization = authorizationService.findByToken(
            normalizeUserCode(userCode),
            OAuth2TokenType(OAuth2ParameterNames.USER_CODE),
        ) ?: reject("user_code_invalid")
        val userCodeToken = authorization.getToken(OAuth2UserCode::class.java)
            ?: reject("user_code_invalid")
        val deviceCodeToken = authorization.getToken(OAuth2DeviceCode::class.java)
            ?: reject("user_code_invalid")
        if (!userCodeToken.isActive || !deviceCodeToken.isActive) {
            reject("user_code_expired")
        }
        if (authorization.authorizationGrantType != AuthorizationGrantType.DEVICE_CODE) {
            reject("user_code_invalid")
        }
        val registeredClient = registeredClientRepository.findById(authorization.registeredClientId)
            ?: reject("user_code_invalid")
        if (registeredClient.clientId != cameraClientId) {
            reject("client_not_allowed")
        }
        val requestedScopes = authorization.getAttribute<Set<String>>(OAuth2ParameterNames.SCOPE).orEmpty()
        if (requestedScopes != setOf(IdpScopes.EVENTS_STREAM)) {
            reject("scope_not_allowed")
        }

        val now = Instant.now(clock)
        val absoluteExpiresAt = now.plus(grantMaxLifetime)
        repository.findUnrevokedByEventAndEdge(eventId, edgeDeviceId).forEach { existing ->
            repository.markRevoked(existing.id, now, "superseded")
            revokeAuthorization(existing.id, now)
        }

        val grant = DeviceGrant(
            id = authorization.id,
            tenantId = staff.tenantId,
            eventId = eventId,
            edgeDeviceId = edgeDeviceId,
            approverSubject = staff.subject,
            clientId = registeredClient.clientId,
            approvedAt = now,
            absoluteExpiresAt = absoluteExpiresAt,
            createdAt = now,
        )
        repository.insert(grant)

        val staffPrincipal = UsernamePasswordAuthenticationToken.authenticated(
            staff.subject,
            null,
            emptyList(),
        )
        val updatedAuthorization = OAuth2Authorization.from(authorization)
            .principalName(staff.subject)
            .authorizedScopes(setOf(IdpScopes.EVENTS_STREAM))
            .attribute(Principal::class.java.name, staffPrincipal)
            .attribute(DEVICE_GRANT_ID_ATTRIBUTE, grant.id)
            .attributes { attributes -> attributes.remove(OAuth2ParameterNames.SCOPE) }
            .invalidate(userCodeToken.token)
            .build()
        authorizationService.save(updatedAuthorization)

        auditService.record(
            TokenAuditEvent(
                clientId = registeredClient.clientId,
                subject = staff.subject,
                requestedTokenUse = TOKEN_USE_EVENT_ACCESS,
                requestedScope = listOf(IdpScopes.EVENTS_STREAM),
                issuedScope = listOf(IdpScopes.EVENTS_STREAM),
                tenantId = staff.tenantId,
                eventId = eventId,
                edgeDeviceId = edgeDeviceId,
                result = "success",
            ),
        )
        log.structuredInfo(
            "Device authorization approved",
            "event" to "device_authorization_approved",
            "client_id" to registeredClient.clientId,
            "tenant_id" to staff.tenantId,
            "event_id" to eventId,
            "edge_device_id" to edgeDeviceId,
            "result" to "success",
        )
        return grant
    }

    @Transactional
    fun revoke(eventId: String, edgeDeviceId: String) {
        requireEventAndEdge(eventId, edgeDeviceId)
        repository.lockEdgeDevice(edgeDeviceId)
        val now = Instant.now(clock)
        if (!repository.isRevoked(eventId, edgeDeviceId)) {
            repository.markEdgeDeviceRevoked(eventId, edgeDeviceId, now)
        }
        val revoked = repository.findUnrevokedByEventAndEdge(eventId, edgeDeviceId)
        repository.markRevokedForEventAndEdge(eventId, edgeDeviceId, now, "bff_revocation")
        revoked.forEach { grant -> revokeAuthorization(grant.id, now) }
        auditService.record(
            TokenAuditEvent(
                clientId = properties.deviceAuthorization.bffClientId,
                requestedTokenUse = "revocation",
                tenantId = revoked.firstOrNull()?.tenantId,
                eventId = eventId,
                edgeDeviceId = edgeDeviceId,
                result = "success",
            ),
        )
        log.structuredInfo(
            "Device authorization revoked",
            "event" to "device_grant_revoked",
            "event_id" to eventId,
            "edge_device_id" to edgeDeviceId,
            "revoked_grant_count" to revoked.size,
            "result" to "success",
        )
    }

    fun requireActiveGrant(authorizationId: String?, clientId: String): DeviceGrant {
        val grant = authorizationId?.let(repository::findById)
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        if (grant.clientId != clientId || !grant.clientId.equals(cameraClientId)) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
        val now = Instant.now(clock)
        if (grant.revokedAt != null ||
            !now.isBefore(grant.absoluteExpiresAt) ||
            repository.isRevoked(grant.eventId, grant.edgeDeviceId)
        ) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
        try {
            requireEventRole(grant.tenantId, grant.approverSubject, grant.eventId)
        } catch (_: StaffNotAuthorizedException) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
        return grant
    }

    fun findByAuthorizationId(authorizationId: String?): DeviceGrant? =
        authorizationId?.let(repository::findById)

    fun recordIssuedRefreshToken(authorizationId: String, refreshToken: OAuth2RefreshToken) {
        val grant = repository.findById(authorizationId) ?: return
        if (grant.clientId != cameraClientId) return
        val hash = hash(refreshToken.tokenValue)
        if (repository.findRefreshToken(hash) == null) {
            repository.insertRefreshToken(
                DeviceGrantRefreshToken(
                    tokenHash = hash,
                    grantId = grant.id,
                    issuedAt = refreshToken.issuedAt ?: Instant.now(clock),
                    expiresAt = refreshToken.expiresAt ?: grant.absoluteExpiresAt,
                ),
            )
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    fun handleReusedRefreshToken(refreshTokenValue: String): Boolean {
        val record = repository.findRefreshToken(hash(refreshTokenValue)) ?: return false
        val grant = repository.findById(record.grantId) ?: return false
        if (grant.revokedAt != null) {
            return true
        }
        val now = Instant.now(clock)
        repository.markRevoked(grant.id, now, "refresh_token_reuse")
        repository.markEdgeDeviceRevoked(grant.eventId, grant.edgeDeviceId, now)
        revokeAuthorization(grant.id, now)
        auditService.record(
            TokenAuditEvent(
                clientId = grant.clientId,
                subject = grant.approverSubject,
                requestedTokenUse = "revocation",
                tenantId = grant.tenantId,
                eventId = grant.eventId,
                edgeDeviceId = grant.edgeDeviceId,
                result = "success",
                failureReason = "refresh_token_reuse",
            ),
        )
        log.structuredWarn(
            "Device authorization revoked after refresh token reuse",
            "event" to "device_grant_refresh_token_reuse",
            "client_id" to grant.clientId,
            "tenant_id" to grant.tenantId,
            "event_id" to grant.eventId,
            "edge_device_id" to grant.edgeDeviceId,
            "result" to "revoked",
        )
        return true
    }

    fun rotateRefreshToken(grant: DeviceGrant, oldTokenValue: String, newToken: OAuth2RefreshToken) {
        val oldHash = hash(oldTokenValue)
        val newHash = hash(newToken.tokenValue)
        if (oldHash == newHash) {
            return
        }
        val now = Instant.now(clock)
        repository.supersedeRefreshToken(grant.id, oldHash, now)
        if (repository.findRefreshToken(newHash) == null) {
            repository.insertRefreshToken(
                DeviceGrantRefreshToken(
                    tokenHash = newHash,
                    grantId = grant.id,
                    issuedAt = newToken.issuedAt ?: Instant.now(clock),
                    expiresAt = newToken.expiresAt ?: grant.absoluteExpiresAt,
                ),
            )
        }
    }

    private fun verifyStaffToken(token: String?, allowedAudiences: Set<String>): VerifiedStaff {
        if (token.isNullOrBlank()) throw StaffTokenInvalidException()
        val jwt = try {
            jwtDecoder.decode(token)
        } catch (_: JwtException) {
            throw StaffTokenInvalidException()
        }
        if (jwt.issuer?.toString() != properties.issuer) throw StaffTokenInvalidException()
        if (jwt.getClaimAsString("token_use") != TOKEN_USE_TENANT_ACCESS) throw StaffTokenInvalidException()
        val subject = jwt.subject?.takeIf { it.isNotBlank() } ?: throw StaffTokenInvalidException()
        val tenantId = jwt.getClaimAsString("tenant_id")?.takeIf { it.isNotBlank() }
            ?: throw StaffTokenInvalidException()
        try {
            resourceParser.requireValidId(tenantId)
        } catch (_: RuntimeException) {
            throw StaffTokenInvalidException()
        }
        val audiences = jwt.audience.orEmpty()
        if (audiences.isEmpty() || audiences.any { it !in allowedAudiences }) {
            throw StaffTokenInvalidException()
        }
        try {
            users.requireTenantUser(tenantId, subject)
        } catch (_: RelationLookupException) {
            throw StaffNotAuthorizedException()
        }
        return VerifiedStaff(tenantId, subject)
    }

    private fun requireEventRole(tenantId: String, subject: String, eventId: String) {
        val user = try {
            users.requireTenantUser(tenantId, subject)
        } catch (_: RelationLookupException) {
            throw StaffNotAuthorizedException()
        }
        val membership = try {
            relationService.getMembership(tenantId, user.username)
        } catch (_: RelationLookupException) {
            throw StaffNotAuthorizedException()
        }
        if (membership.events.none { it.eventId == eventId }) {
            throw StaffNotAuthorizedException()
        }
    }

    private fun requireEventAndEdge(eventId: String, edgeDeviceId: String) {
        try {
            resourceParser.requireValidId(eventId)
        } catch (_: RuntimeException) {
            reject("event_id_invalid")
        }
        if (!EDGE_DEVICE_ID_PATTERN.matches(edgeDeviceId)) {
            reject("edge_device_id_invalid")
        }
    }

    private fun revokeAuthorization(authorizationId: String, now: Instant) {
        val authorization = authorizationService.findById(authorizationId) ?: return
        denyAccessToken(authorization, now)
        val builder = OAuth2Authorization.from(authorization)
        val refreshToken = authorization.refreshToken?.token
        if (refreshToken != null) {
            builder.invalidate(refreshToken)
        } else {
            authorization.accessToken?.token?.let(builder::invalidate)
        }
        authorizationService.save(builder.build())
    }

    private fun denyAccessToken(authorization: OAuth2Authorization, now: Instant) {
        val accessToken = authorization.accessToken ?: return
        val claims = accessToken.claims ?: return
        val jti = claims["jti"] as? String ?: return
        val expiresAt = claimInstant(claims["exp"])
            ?: accessToken.token.expiresAt
            ?: return
        if (!expiresAt.isAfter(now) || jtiDenylistRepository.existsById(jti)) {
            return
        }
        jtiDenylistRepository.save(
            JtiDenylistEntry(jti = jti, expiresAt = expiresAt).apply { isNewEntity = true },
        )
    }

    private fun claimInstant(value: Any?): Instant? =
        when (value) {
            is Instant -> value
            is Number -> Instant.ofEpochSecond(value.toLong())
            else -> null
        }

    private fun normalizeUserCode(value: String): String {
        val normalized = value.uppercase(Locale.ROOT).replace(Regex("[^A-Z0-9]"), "")
        if (normalized.length != 8) reject("user_code_invalid")
        return normalized.substring(0, 4) + "-" + normalized.substring(4)
    }

    private fun hash(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte) }

    private fun reject(reason: String): Nothing = throw DeviceGrantRejectedException(reason)

    private data class VerifiedStaff(
        val tenantId: String,
        val subject: String,
    )

    private companion object {
        val log = LoggerFactory.getLogger(DeviceGrantService::class.java)
        val EDGE_DEVICE_ID_PATTERN = Regex("^[0-9a-f]{16}$")
    }
}
