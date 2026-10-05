package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.logging.structuredDebug
import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredTrace
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopeNotAllowedException
import dev.usbharu.toloidp.scope.ScopePolicy
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/**
 * このリポジトリの OAuth2 tenant-access から event-access への Token Exchange 仕様を実装する
 * authentication provider。
 *
 * Spring Authorization Server のデフォルト Token Exchange provider を置き換え、audience /
 * resource / client policy / subject token / membership / scope / denylist / audit の要件を
 * 1 つの認可境界で強制する。
 */
open class SpecTokenExchangeAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>,
    private val clientPolicyRepository: ClientPolicyRepository,
    private val resourceParser: ResourceParser,
    private val relationService: RelationService,
    private val scopePolicy: ScopePolicy,
    private val jtiDenylistRepository: JtiDenylistRepository,
    private val auditService: AuditService,
    private val clock: Clock,
) : AuthenticationProvider {
    /**
     * Token Exchange リクエストを認証し、すべての仕様チェックに成功した場合だけ単一の
     * event access token を発行する。
     */
    @Transactional
    override fun authenticate(authentication: Authentication): Authentication {
        log.structuredTrace(
            "Token Exchange authentication started",
            "event" to "token_exchange_authentication_started",
            "authentication_type" to authentication::class.java.simpleName,
        )
        val tokenExchange = authentication as OAuth2TokenExchangeAuthenticationToken
        val clientPrincipal = authenticatedClient(tokenExchange)
        val registeredClient = clientPrincipal.registeredClient
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_client"))
        val requestedScopes = tokenExchange.scopes
        log.structuredInfo(
            "Token Exchange started",
            "event" to "token_exchange_started",
            "client_id" to registeredClient.clientId,
            "audience_count" to tokenExchange.audiences.size,
            "resource_count" to tokenExchange.resources.size,
            "scope_count" to requestedScopes.size,
        )
        var audit = TokenAuditEvent(
            clientId = registeredClient.clientId,
            requestedTokenUse = TOKEN_USE_EVENT_ACCESS,
            requestedAudience = tokenExchange.audiences.singleOrNull(),
            requestedResource = tokenExchange.resources.singleOrNull(),
            requestedScope = requestedScopes.toList(),
            result = "failure",
        )

        try {
            val policy = clientPolicyRepository.findByClientId(registeredClient.clientId)
                ?: fail("invalid_request", "client_not_allowed")
            log.structuredDebug(
                "Client policy lookup completed",
                "event" to "client_policy_lookup_completed",
                "client_id" to registeredClient.clientId,
                "client_type" to policy.clientType,
                "allowed_audience_count" to policy.allowedAudiences.size,
                "allowed_scope_count" to policy.allowedScopes.size,
            )
            if (policy.clientType != ClientType.CONFIDENTIAL) {
                fail("invalid_grant", "client_not_allowed")
            }
            if (AuthorizationGrantType.TOKEN_EXCHANGE.value !in policy.allowedGrantTypes ||
                TOKEN_EXCHANGE_TRANSITION_TENANT_TO_EVENT !in policy.allowedTransitions
            ) {
                fail("invalid_grant", "invalid_token_use_transition")
            }
            if (tokenExchange.subjectTokenType != ACCESS_TOKEN_TYPE) {
                fail("invalid_request", "subject_token_type")
            }
            val audience = tokenExchange.audiences.singleOrNull()
                ?: fail("invalid_target", "audience_not_allowed")
            if (audience !in policy.allowedAudiences) {
                fail("invalid_target", "audience_not_allowed")
            }
            val eventResource = try {
                resourceParser.parseEvent(tokenExchange.resources.singleOrNull() ?: fail("invalid_target", "resource_invalid_format"))
            } catch (ex: RuntimeException) {
                fail("invalid_target", "resource_invalid_format")
            }

            val subjectAuthorization = authorizationService.findByToken(tokenExchange.subjectToken, OAuth2TokenType.ACCESS_TOKEN)
                ?: fail("invalid_grant", "token_revoked")
            log.structuredDebug(
                "Subject token lookup completed",
                "event" to "subject_token_lookup_completed",
                "client_id" to registeredClient.clientId,
                "found" to true,
            )
            val subjectToken = subjectAuthorization.getToken<OAuth2Token>(tokenExchange.subjectToken)
                ?: fail("invalid_grant", "token_revoked")
            val claims = subjectToken.claims ?: fail("invalid_grant", "token_revoked")
            val subjectAudience = singleAudience(claims["aud"])
                ?: fail("invalid_grant", "subject_token_invalid_claims")
            if (subjectAudience != audience) {
                fail("invalid_grant", "subject_token_audience_mismatch")
            }
            val subjectJti = claims["jti"] as? String
                ?: fail("invalid_grant", "subject_token_invalid_claims")
            val denied = isDenied(subjectJti)
            log.structuredDebug(
                "Subject token status checked",
                "event" to "subject_token_status_checked",
                "client_id" to registeredClient.clientId,
                "active" to subjectToken.isActive,
                "jti_present" to (claims["jti"] is String),
                "denied" to denied,
            )
            if (!subjectToken.isActive || denied) {
                fail("invalid_grant", "token_revoked")
            }
            if (subjectAuthorization.registeredClientId != registeredClient.id ||
                claims["client_id"] != registeredClient.clientId
            ) {
                fail("invalid_grant", "subject_token_client_mismatch")
            }
            val subject = claims["sub"] as? String
                ?: fail("invalid_grant", "subject_token_invalid_claims")
            audit = audit.copy(
                subject = subject,
                sourceTokenUse = claims["token_use"] as? String,
                tenantId = eventResource.tenantId,
                eventId = eventResource.eventId,
            )
            if (claims["token_use"] != TOKEN_USE_TENANT_ACCESS) {
                fail("invalid_grant", "invalid_token_use_transition")
            }
            val subjectTenantId = claims["tenant_id"] as? String
                ?: fail("invalid_grant", "subject_token_invalid_claims")
            val subjectResource = try {
                resourceParser.parseTenant(claims["resource"] as? String ?: fail("invalid_grant", "subject_token_invalid_claims"))
            } catch (ex: RuntimeException) {
                fail("invalid_grant", "subject_token_invalid_claims")
            }
            if (subjectResource.tenantId != subjectTenantId) {
                fail("invalid_grant", "subject_token_invalid_claims")
            }
            if (subjectTenantId != eventResource.tenantId) {
                fail("invalid_grant", "event_not_in_tenant")
            }
            val subjectScopes = splitScope(claims["scope"])
            try {
                scopePolicy.requireAllowed(requestedScopes, policy.allowedScopes, "scope_not_allowed_for_client")
                scopePolicy.requireEventAccessScopes(requestedScopes)
                scopePolicy.requireAllowed(requestedScopes, subjectScopes, "scope_exceeds_subject_token")
                val membership = relationService.getMembership(eventResource.tenantId, subject)
                log.structuredDebug(
                    "Relation membership lookup completed",
                    "event" to "relation_membership_lookup_completed",
                    "client_id" to registeredClient.clientId,
                    "tenant_id" to eventResource.tenantId,
                    "subject" to subject,
                    "event_count" to membership.events.size,
                )
                val eventMembership = membership.events.find { it.eventId == eventResource.eventId }
                    ?: fail("invalid_grant", "user_not_event_member")
                scopePolicy.requireAllowed(requestedScopes, scopePolicy.allowedScopes(eventMembership.role), "scope_not_allowed_for_role")
            } catch (ex: ScopeNotAllowedException) {
                log.structuredWarn(
                    "Token Exchange scope validation failed",
                    ex,
                    "event" to "token_exchange_scope_validation_failed",
                    "client_id" to registeredClient.clientId,
                    "tenant_id" to eventResource.tenantId,
                    "event_id" to eventResource.eventId,
                    "scope_count" to requestedScopes.size,
                    "failure_reason" to ex.reason,
                )
                val code = if (ex.reason == "scope_exceeds_subject_token") "invalid_grant" else "invalid_scope"
                fail(code, ex.reason)
            } catch (ex: RelationLookupException) {
                log.structuredWarn(
                    "Token Exchange relation lookup failed",
                    ex,
                    "event" to "token_exchange_relation_lookup_failed",
                    "client_id" to registeredClient.clientId,
                    "tenant_id" to eventResource.tenantId,
                    "event_id" to eventResource.eventId,
                    "subject" to subject,
                    "failure_reason" to ex.reason,
                )
                fail("invalid_grant", ex.reason)
            }

            val principal = subjectAuthorization.getAttribute<Authentication>(java.security.Principal::class.java.name)
                ?: fail("invalid_grant", "token_revoked")
            val tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorization(subjectAuthorization)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(requestedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrant(tokenExchange)
                .build()
            val generatedAccessToken = tokenGenerator.generate(tokenContext)
                ?: fail("server_error", "token_generation_failed")
            val accessToken = toAccessToken(registeredClient, generatedAccessToken, requestedScopes)

            val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(subjectAuthorization.principalName)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizedScopes(requestedScopes)
                .attribute(java.security.Principal::class.java.name, principal)
            authorizationBuilder.token(accessToken) {
                if (generatedAccessToken is Jwt) {
                    it[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = generatedAccessToken.claims
                }
                it[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = false
                it[OAuth2TokenFormat::class.java.name] = OAuth2TokenFormat.SELF_CONTAINED.value
            }
            authorizationService.save(authorizationBuilder.build())
            auditService.record(
                audit.copy(
                    issuedScope = requestedScopes.toList(),
                    result = "success",
                    failureReason = null,
                    issuedJti = (generatedAccessToken as? Jwt)?.id,
                ),
            )
            log.structuredInfo(
                "Token Exchange completed",
                "event" to "token_exchange_completed",
                "client_id" to registeredClient.clientId,
                "tenant_id" to audit.tenantId,
                "event_id" to audit.eventId,
                "scope_count" to requestedScopes.size,
                "result" to "success",
            )
            log.structuredTrace("Token Exchange authentication completed", "event" to "token_exchange_authentication_completed", "client_id" to registeredClient.clientId, "result" to "success")
            return OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                null,
                mapOf(OAuth2ParameterNames.ISSUED_TOKEN_TYPE to ACCESS_TOKEN_TYPE),
            )
        } catch (ex: SpecOAuth2Failure) {
            auditService.record(audit.copy(result = "failure", failureReason = ex.failureReason))
            log.structuredInfo(
                "Token Exchange failed",
                "event" to "token_exchange_failed",
                "client_id" to registeredClient.clientId,
                "error_code" to ex.errorCode,
                "failure_reason" to ex.failureReason,
                "audience_count" to tokenExchange.audiences.size,
                "resource_count" to tokenExchange.resources.size,
                "scope_count" to requestedScopes.size,
                "result" to "failure",
            )
            log.structuredTrace("Token Exchange authentication completed", "event" to "token_exchange_authentication_completed", "client_id" to registeredClient.clientId, "result" to "failure")
            throw OAuth2AuthenticationException(OAuth2Error(ex.errorCode))
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2TokenExchangeAuthenticationToken::class.java.isAssignableFrom(authentication)

    private fun authenticatedClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
        val principal = authentication.principal
        if (principal is OAuth2ClientAuthenticationToken && principal.isAuthenticated) {
            return principal
        }
        throw OAuth2AuthenticationException(OAuth2Error("invalid_client"))
    }

    private fun toAccessToken(
        registeredClient: RegisteredClient,
        token: OAuth2Token,
        scopes: Set<String>,
    ): OAuth2AccessToken =
        OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            token.tokenValue,
            token.issuedAt,
            token.expiresAt,
            scopes,
        )

    private fun isDenied(jti: String?): Boolean {
        if (jti == null) {
            return false
        }
        return jtiDenylistRepository.existsByJtiAndExpiresAtAfter(jti, Instant.now(clock))
    }

    private fun splitScope(value: Any?): Set<String> =
        when (value) {
            is String -> value.split(' ').filter { it.isNotEmpty() }.toSet()
            is Collection<*> -> value.filterIsInstance<String>().toSet()
            else -> emptySet()
        }

    private fun singleAudience(value: Any?): String? =
        when (value) {
            is String -> value
            is Collection<*> -> value.singleOrNull() as? String
            else -> null
        }

    private fun fail(errorCode: String, reason: String): Nothing {
        throw SpecOAuth2Failure(errorCode, reason)
    }

    companion object {
        private val log = LoggerFactory.getLogger(SpecTokenExchangeAuthenticationProvider::class.java)
    }
}

private class SpecOAuth2Failure(
    val errorCode: String,
    val failureReason: String,
) : RuntimeException(failureReason)
