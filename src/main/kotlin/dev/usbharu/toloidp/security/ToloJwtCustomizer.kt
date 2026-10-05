package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.logging.structuredDebug
import dev.usbharu.toloidp.logging.structuredTrace
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopeNotAllowedException
import dev.usbharu.toloidp.scope.ScopePolicy
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.UUID

/**
 * access token JWT に仕様で定義した claim を追加する customizer。
 *
 * Authorization Code grant では tenant access token、Token Exchange grant では event access
 * token を生成する。role claim は意図的に入れず、Resource Server が token context と自身の
 * policy から最終認可を行う。
 */
@Component
class ToloJwtCustomizer(
    private val clientPolicyRepository: ClientPolicyRepository,
    private val resourceParser: ResourceParser,
    private val relationService: RelationService,
    private val scopePolicy: ScopePolicy,
) : OAuth2TokenCustomizer<JwtEncodingContext> {
    /**
     * access token だけを対象にし、grant type ごとの claim 付与処理へ委譲する。
     */
    override fun customize(context: JwtEncodingContext) {
        if (context.tokenType != OAuth2TokenType.ACCESS_TOKEN) {
            return
        }
        when (context.authorizationGrantType) {
            AuthorizationGrantType.AUTHORIZATION_CODE -> customizeTenantAccess(context)
            AuthorizationGrantType.TOKEN_EXCHANGE -> customizeEventAccess(context)
        }
    }

    private fun customizeTenantAccess(context: JwtEncodingContext) {
        val clientId = context.registeredClient.clientId
        log.structuredTrace(
            "Tenant access JWT customization started",
            "event" to "tenant_access_jwt_customization_started",
            "client_id" to clientId,
            "scope_count" to context.authorizedScopes.size,
        )
        val policy = clientPolicyRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException("invalid_request")
        if (AuthorizationGrantType.AUTHORIZATION_CODE.value !in policy.allowedGrantTypes) {
            throw OAuth2AuthenticationException(OAuth2Error("unauthorized_client"))
        }
        log.structuredDebug(
            "Tenant access client policy loaded",
            "event" to "tenant_access_client_policy_loaded",
            "client_id" to clientId,
            "allowed_audience_count" to policy.allowedAudiences.size,
            "allowed_scope_count" to policy.allowedScopes.size,
        )
        val authorizationRequest = context.authorization
            ?.getAttribute<OAuth2AuthorizationRequest>(OAuth2AuthorizationRequest::class.java.name)
            ?: throw OAuth2AuthenticationException("invalid_grant")
        val resource = authorizationRequest.additionalParameters[OAuth2ParameterNames.RESOURCE] as? String
            ?: throw OAuth2AuthenticationException("invalid_grant")
        val tenantResource = try {
            resourceParser.parseTenant(resource)
        } catch (ex: RuntimeException) {
            log.structuredWarn(
                "Tenant access JWT customization rejected",
                ex,
                "event" to "tenant_access_jwt_customization_rejected",
                "client_id" to clientId,
                "failure_reason" to "invalid_resource",
            )
            throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        }
        val audienceParameter = authorizationRequest.additionalParameters[OAuth2ParameterNames.AUDIENCE]
        val audience = when (audienceParameter) {
            null -> policy.allowedAudiences.singleOrNull()
                ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
            is String -> audienceParameter
            else -> throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        }
        if (audience !in policy.allowedAudiences) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        }

        try {
            val principal = context.getPrincipal<org.springframework.security.core.Authentication>()
            val membership = relationService.getMembership(tenantResource.tenantId, principal.name)
            log.structuredDebug(
                "Tenant access membership loaded",
                "event" to "tenant_access_membership_loaded",
                "client_id" to clientId,
                "tenant_id" to tenantResource.tenantId,
                "subject" to principal.name,
                "tenant_role" to membership.tenantRole,
            )
            scopePolicy.requireAllowed(context.authorizedScopes, policy.allowedScopes, "scope_not_allowed_for_client")
            scopePolicy.requireTenantAccessScopes(context.authorizedScopes, membership.tenantRole, "scope_not_allowed_for_role")
        } catch (ex: ScopeNotAllowedException) {
            log.structuredWarn(
                "Tenant access scope validation failed",
                ex,
                "event" to "tenant_access_scope_validation_failed",
                "client_id" to clientId,
                "tenant_id" to tenantResource.tenantId,
                "scope_count" to context.authorizedScopes.size,
                "failure_reason" to ex.reason,
            )
            throw OAuth2AuthenticationException(OAuth2Error("invalid_scope"))
        } catch (ex: RelationLookupException) {
            log.structuredWarn(
                "Tenant access relation lookup failed",
                ex,
                "event" to "tenant_access_relation_lookup_failed",
                "client_id" to clientId,
                "tenant_id" to tenantResource.tenantId,
                "failure_reason" to ex.reason,
            )
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }

        val now = Instant.now()
        context.claims
            .audience(listOf(audience))
            .issuedAt(now)
            .notBefore(now)
            .expiresAt(now.plus(policy.tenantAccessTtl))
            .id(UUID.randomUUID().toString())
            .claim("client_id", clientId)
            .claim("scope", context.authorizedScopes.joinToString(" "))
            .claim("token_use", TOKEN_USE_TENANT_ACCESS)
            .claim("resource", tenantResource.value)
            .claim("tenant_id", tenantResource.tenantId)
        log.structuredDebug(
            "Tenant access JWT claims customized",
            "event" to "tenant_access_jwt_claims_customized",
            "client_id" to clientId,
            "tenant_id" to tenantResource.tenantId,
            "audience" to audience,
            "scope_count" to context.authorizedScopes.size,
            "result" to "success",
        )
        log.structuredTrace("Tenant access JWT customization completed", "event" to "tenant_access_jwt_customization_completed", "client_id" to clientId, "tenant_id" to tenantResource.tenantId)
    }

    private fun customizeEventAccess(context: JwtEncodingContext) {
        log.structuredTrace(
            "Event access JWT customization started",
            "event" to "event_access_jwt_customization_started",
            "client_id" to context.registeredClient.clientId,
            "scope_count" to context.authorizedScopes.size,
        )
        val tokenExchange = context.getAuthorizationGrant<OAuth2TokenExchangeAuthenticationToken>()
        val policy = clientPolicyRepository.findByClientId(context.registeredClient.clientId)
            ?: throw OAuth2AuthenticationException("invalid_request")
        val resource = tokenExchange.resources.singleOrNull()
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        val eventResource = try {
            resourceParser.parseEvent(resource)
        } catch (ex: RuntimeException) {
            log.structuredWarn(
                "Event access JWT customization rejected",
                ex,
                "event" to "event_access_jwt_customization_rejected",
                "client_id" to context.registeredClient.clientId,
                "failure_reason" to "invalid_resource",
            )
            throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        }
        val audience = tokenExchange.audiences.singleOrNull()
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))

        val now = Instant.now()
        context.claims
            .audience(listOf(audience))
            .issuedAt(now)
            .notBefore(now)
            .expiresAt(now.plus(policy.eventAccessTtl))
            .id(UUID.randomUUID().toString())
            .claim("client_id", context.registeredClient.clientId)
            .claim("scope", context.authorizedScopes.joinToString(" "))
            .claim("token_use", TOKEN_USE_EVENT_ACCESS)
            .claim("resource", eventResource.value)
            .claim("tenant_id", eventResource.tenantId)
            .claim("event_id", eventResource.eventId)
        log.structuredDebug(
            "Event access JWT claims customized",
            "event" to "event_access_jwt_claims_customized",
            "client_id" to context.registeredClient.clientId,
            "tenant_id" to eventResource.tenantId,
            "event_id" to eventResource.eventId,
            "audience" to audience,
            "scope_count" to context.authorizedScopes.size,
            "result" to "success",
        )
        log.structuredTrace(
            "Event access JWT customization completed",
            "event" to "event_access_jwt_customization_completed",
            "client_id" to context.registeredClient.clientId,
            "tenant_id" to eventResource.tenantId,
            "event_id" to eventResource.eventId,
        )
    }

    companion object {
        private val log = LoggerFactory.getLogger(ToloJwtCustomizer::class.java)
    }
}
