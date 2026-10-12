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
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator
import java.util.function.Consumer

/**
 * tenant scope の access token 発行に使う Authorization Code request validator。
 *
 * Spring Authorization Server のデフォルト検証に加えて、tenant access JWT 発行前に必要な
 * client policy / tenant resource / audience / relation membership / scope を検証する。
 */
class TenantAuthorizationValidator(
    private val clientPolicyRepository: ClientPolicyRepository,
    private val resourceParser: ResourceParser,
    private val relationService: RelationService,
    private val scopePolicy: ScopePolicy,
) : Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {
    private val defaultValidator = OAuth2AuthorizationCodeRequestAuthenticationValidator()

    /**
     * tenant や membership の詳細を OAuth2 error code 以上に漏らさず、authorization request を検証する。
     */
    override fun accept(context: OAuth2AuthorizationCodeRequestAuthenticationContext) {
        log.structuredTrace("Tenant authorization validation started", "event" to "tenant_authorization_validation_started", "client_id" to context.registeredClient.clientId)
        defaultValidator.accept(context)
        val authentication = context.getAuthentication<OAuth2AuthorizationCodeRequestAuthenticationToken>()
        val clientId = context.registeredClient.clientId
        val policy = clientPolicyRepository.findByClientId(clientId)
            ?: throwAuthorizationError(OAuth2ErrorCodes.INVALID_REQUEST, "client_id")
        log.structuredDebug(
            "Authorization request client policy loaded",
            "event" to "authorization_request_client_policy_loaded",
            "client_id" to clientId,
            "allowed_audience_count" to policy.allowedAudiences.size,
            "allowed_scope_count" to policy.allowedScopes.size,
        )
        if (AuthorizationGrantType.AUTHORIZATION_CODE.value !in policy.allowedGrantTypes) {
            throwAuthorizationError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "client_id")
        }

        val resource = authentication.additionalParameters[OAuth2ParameterNames.RESOURCE] as? String
            ?: throwAuthorizationError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESOURCE)
        val tenantResource = try {
            resourceParser.parseTenant(resource)
        } catch (ex: RuntimeException) {
            log.structuredWarn(
                "Authorization request rejected",
                ex,
                "event" to "authorization_request_rejected",
                "client_id" to clientId,
                "failure_reason" to "invalid_tenant_resource",
            )
            throwAuthorizationError("invalid_target", OAuth2ParameterNames.RESOURCE)
        }

        val audienceParameter = authentication.additionalParameters[OAuth2ParameterNames.AUDIENCE]
        val audience = when (audienceParameter) {
            null -> policy.allowedAudiences.singleOrNull()
                ?: throwAuthorizationError("invalid_target", OAuth2ParameterNames.AUDIENCE)
            is String -> audienceParameter
            else -> throwAuthorizationError("invalid_target", OAuth2ParameterNames.AUDIENCE)
        }
        if (audience !in policy.allowedAudiences) {
            throwAuthorizationError("invalid_target", OAuth2ParameterNames.AUDIENCE)
        }

        val requestedScopes = authentication.scopes.orEmpty()
        try {
            scopePolicy.requireAllowed(requestedScopes, policy.allowedScopes, "scope_not_allowed_for_client")
            val membership = relationService.getMembership(tenantResource.tenantId, (authentication.principal as org.springframework.security.core.Authentication).name)
            log.structuredDebug(
                "Authorization request membership loaded",
                "event" to "authorization_request_membership_loaded",
                "client_id" to clientId,
                "tenant_id" to tenantResource.tenantId,
                "subject" to (authentication.principal as org.springframework.security.core.Authentication).name,
                "tenant_role" to membership.tenantRole,
                "scope_count" to requestedScopes.size,
            )
            scopePolicy.requireTenantAccessScopes(requestedScopes, membership.tenantRole, "scope_not_allowed_for_role")
        } catch (ex: ScopeNotAllowedException) {
            log.structuredWarn(
                "Authorization request scope validation failed",
                ex,
                "event" to "authorization_request_scope_validation_failed",
                "client_id" to clientId,
                "tenant_id" to tenantResource.tenantId,
                "scope_count" to requestedScopes.size,
                "failure_reason" to ex.reason,
            )
            throwAuthorizationError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE)
        } catch (ex: RelationLookupException) {
            log.structuredWarn(
                "Authorization request relation lookup failed",
                ex,
                "event" to "authorization_request_relation_lookup_failed",
                "client_id" to clientId,
                "tenant_id" to tenantResource.tenantId,
                "failure_reason" to ex.reason,
            )
            throwAuthorizationError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.RESOURCE)
        }
        log.structuredDebug(
            "Authorization request validation completed",
            "event" to "authorization_request_validation_completed",
            "client_id" to clientId,
            "tenant_id" to tenantResource.tenantId,
            "audience" to audience,
            "scope_count" to requestedScopes.size,
            "result" to "success",
        )
        log.structuredTrace("Tenant authorization validation completed", "event" to "tenant_authorization_validation_completed", "client_id" to clientId, "tenant_id" to tenantResource.tenantId)
    }

    private fun throwAuthorizationError(errorCode: String, parameter: String): Nothing {
        val error = OAuth2Error(errorCode, "OAuth 2.0 Parameter: $parameter", null)
        throw OAuth2AuthorizationCodeRequestAuthenticationException(error, null)
    }

    companion object {
        private val log = LoggerFactory.getLogger(TenantAuthorizationValidator::class.java)
    }
}
