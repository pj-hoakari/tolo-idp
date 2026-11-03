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
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
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
        reapproval: Boolean = false,
    ): DeviceGrant {
        requireEventAndEdge(eventId, edgeDeviceId)
        val bffPolicy = ClientPolicy.from(bffClient) ?: throw BffAuthenticationException()
        val staff = verifyStaffToken(staffToken, bffPolicy.allowedAudiences)
        requireEventRole(staff.tenantId, staff.subject, eventId)

        repository.lockEdgeDevice(edgeDeviceId)
        // Re-read the revocation under the per-edge lock so a concurrent revoke cannot be missed.
        val revocation = repository.findRevocation(eventId, edgeDeviceId)
        if (revocation != null) {
            when {
                revocation.permanent -> reject("edge_device_revoked")
                !reapproval -> reject("edge_device_reapproval_required")
                else -> {
                    repository.clearTemporaryRevocation(eventId, edgeDeviceId)
                    log.structuredInfo(
                        "Temporary device revocation cleared by explicit reapproval",
                        "event" to "device_grant_reapproval",
                        "event_id" to eventId,
                        "edge_device_id" to edgeDeviceId,
                        "result" to "success",
                    )
                }
            }
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
    fun revoke(eventId: String, edgeDeviceId: String, permanent: Boolean = true) {
        requireEventAndEdge(eventId, edgeDeviceId)
        repository.lockEdgeDevice(edgeDeviceId)
        val now = Instant.now(clock)
        // The repository keeps an existing permanent revocation sticky.
        repository.markEdgeDeviceRevoked(eventId, edgeDeviceId, now, permanent)
        val effectivePermanent = repository.findRevocation(eventId, edgeDeviceId)?.permanent ?: permanent
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
                failureReason = if (effectivePermanent) null else "temporary_revocation",
            ),
        )
        log.structuredInfo(
            "Device authorization revoked",
            "event" to "device_grant_revoked",
            "event_id" to eventId,
            "edge_device_id" to edgeDeviceId,
            "revocation_kind" to if (effectivePermanent) "permanent" else "temporary",
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

    @Transactional(readOnly = true)
    fun findGrantByRefreshToken(refreshTokenValue: String): DeviceGrant? =
        repository.findRefreshToken(hash(refreshTokenValue))
            ?.let { record -> repository.findById(record.grantId) }

    @Transactional
    fun recordIssuedRefreshToken(authorizationId: String, refreshToken: OAuth2RefreshToken) {
        val grant = repository.findById(authorizationId) ?: return
        if (grant.clientId != cameraClientId) return
        insertRefreshTokenRecord(grant, refreshToken)
    }

    /**
     * Performs the whole camera refresh under the per-edge device lock.
     *
     * The old token is consumed with a conditional update, then the standard provider issues
     * and persists the new tokens. The token history update therefore commits with the
     * authorization update, or neither is visible.
     *
     * A rejected outcome is returned after the reuse revocation has committed so the caller
     * can turn it into `invalid_grant` without rolling the revocation back.
     */
    @Transactional
    fun refresh(
        refreshTokenValue: String,
        clientId: String,
        issueTokens: () -> OAuth2AccessTokenAuthenticationToken,
    ): DeviceGrantRefreshOutcome {
        val tokenHash = hash(refreshTokenValue)
        val recorded = repository.findRefreshToken(tokenHash)
            ?: return DeviceGrantRefreshOutcome.Rejected
        val beforeLock = repository.findById(recorded.grantId)
            ?: return DeviceGrantRefreshOutcome.Rejected
        repository.lockEdgeDevice(beforeLock.edgeDeviceId)

        // Re-read the grant, token history and authorization after acquiring the edge lock.
        val record = repository.findRefreshToken(tokenHash)
            ?: return DeviceGrantRefreshOutcome.Rejected
        val grant = repository.findById(record.grantId)
            ?: return DeviceGrantRefreshOutcome.Rejected
        if (grant.edgeDeviceId != beforeLock.edgeDeviceId) {
            return DeviceGrantRefreshOutcome.Rejected
        }
        if (record.supersededAt != null) {
            revokeForReuse(grant)
            return DeviceGrantRefreshOutcome.Rejected
        }
        if (grant.clientId != cameraClientId || grant.clientId != clientId) {
            return DeviceGrantRefreshOutcome.Rejected
        }
        val authorization = authorizationService.findById(grant.id)
            ?: return DeviceGrantRefreshOutcome.Rejected
        if (authorization.principalName != grant.approverSubject) {
            return DeviceGrantRefreshOutcome.Rejected
        }
        if (authorization.refreshToken?.token?.tokenValue != refreshTokenValue) {
            revokeForReuse(grant)
            return DeviceGrantRefreshOutcome.Rejected
        }
        requireActiveGrant(grant.id, clientId)

        val now = Instant.now(clock)
        val consumed = try {
            repository.supersedeRefreshToken(grant.id, tokenHash, now)
        } catch (ex: RuntimeException) {
            throw DeviceGrantRefreshStateException(grant, ex)
        }
        if (consumed == 0) {
            revokeForReuse(grant)
            return DeviceGrantRefreshOutcome.Rejected
        }
        return try {
            val authentication = issueTokens()
            val newRefreshToken = authentication.refreshToken
                ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
            insertRefreshTokenRecord(grant, newRefreshToken)
            DeviceGrantRefreshOutcome.Issued(authentication)
        } catch (ex: Throwable) {
            throw DeviceGrantRefreshStateException(grant, ex)
        }
    }

    /**
     * Fail-closed fallback after a refresh transaction rolled back.
     *
     * The old token must not become usable again if the new token or its history could not be
     * persisted. Runs in its own transaction after the failed transaction has released its locks.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    fun revokeAfterFailedRefresh(grant: DeviceGrant) {
        repository.lockEdgeDevice(grant.edgeDeviceId)
        val current = repository.findById(grant.id) ?: return
        if (current.revokedAt != null) {
            return
        }
        val now = Instant.now(clock)
        repository.markRevoked(current.id, now, "refresh_state_failed")
        repository.markEdgeDeviceRevoked(current.eventId, current.edgeDeviceId, now, permanent = false)
        revokeAuthorization(current.id, now)
        auditService.record(
            TokenAuditEvent(
                clientId = current.clientId,
                subject = current.approverSubject,
                requestedTokenUse = "revocation",
                tenantId = current.tenantId,
                eventId = current.eventId,
                edgeDeviceId = current.edgeDeviceId,
                result = "success",
                failureReason = "refresh_state_failed",
            ),
        )
        log.structuredWarn(
            "Device authorization revoked after refresh state persistence failed",
            "event" to "device_grant_refresh_state_failed",
            "client_id" to current.clientId,
            "tenant_id" to current.tenantId,
            "event_id" to current.eventId,
            "edge_device_id" to current.edgeDeviceId,
            "result" to "revoked",
        )
    }

    private fun revokeForReuse(grant: DeviceGrant) {
        if (grant.revokedAt != null) {
            return
        }
        val now = Instant.now(clock)
        repository.markRevoked(grant.id, now, "refresh_token_reuse")
        repository.markEdgeDeviceRevoked(grant.eventId, grant.edgeDeviceId, now, permanent = false)
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
    }

    private fun insertRefreshTokenRecord(grant: DeviceGrant, refreshToken: OAuth2RefreshToken) {
        val tokenHash = hash(refreshToken.tokenValue)
        if (repository.findRefreshToken(tokenHash) != null) {
            return
        }
        repository.insertRefreshToken(
            DeviceGrantRefreshToken(
                tokenHash = tokenHash,
                grantId = grant.id,
                issuedAt = refreshToken.issuedAt ?: Instant.now(clock),
                expiresAt = refreshToken.expiresAt ?: grant.absoluteExpiresAt,
            ),
        )
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
