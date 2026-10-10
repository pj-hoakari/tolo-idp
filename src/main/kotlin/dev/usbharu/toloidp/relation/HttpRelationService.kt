package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.logging.structuredDebug
import dev.usbharu.toloidp.logging.structuredTrace
import dev.usbharu.toloidp.logging.structuredWarn
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.resource.ResourceValidationException
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.scope.UnknownRelationRoleException
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.client.JdkClientHttpRequestFactory
import org.springframework.stereotype.Service
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException
import java.net.http.HttpClient

/**
 * tenant / event 所属情報の正本として remote relation API を参照する [RelationService] 実装。
 *
 * relation API の応答は受け入れる前に検証し、tenant / user / event / role の不整合を
 * Authorization Server の認可判定へ持ち込まない。
 */
@Service
class HttpRelationService(
    properties: IdpProperties,
    private val resourceParser: ResourceParser,
) : RelationService {
    private val restClient: RestClient = RestClient.builder()
        .baseUrl(properties.relation.baseUrl)
        .requestFactory(
            JdkClientHttpRequestFactory(
                HttpClient.newBuilder()
                    .connectTimeout(properties.relation.connectTimeout)
                    .build(),
            ).apply {
                setReadTimeout(properties.relation.readTimeout)
            },
        )
        .build()

    /**
     * relation API から所属情報を取得し、上流の失敗や不正な応答を内部向けの
     * [RelationLookupException] 理由へ変換する。
     */
    override fun getMembership(tenantId: String, userId: String): TenantMembership {
        log.structuredTrace("Relation membership HTTP lookup started", "event" to "relation_membership_http_lookup_started", "tenant_id" to tenantId, "subject" to userId)
        resourceParser.requireValidId(tenantId)
        val response = getOrNull<MembershipResponse>("/tenants/{tenantId}/users/{userId}", tenantId, userId)
            ?: throw RelationLookupException("tenant_not_found")
        if (response.tenant.id != tenantId || response.user.id != userId) {
            log.structuredWarn(
                "Relation service returned mismatched membership",
                "event" to "relation_membership_response_invalid",
                "tenant_id" to tenantId,
                "subject" to userId,
                "response_tenant_id" to response.tenant.id,
                "response_subject" to response.user.id,
                "failure_reason" to "relation_response_invalid",
            )
            throw RelationLookupException("relation_response_invalid")
        }
        val roleValue = response.tenant.role ?: throw RelationLookupException("user_not_tenant_member")
        val tenantRole = parseRole(roleValue)
        val events = try {
            response.events.map {
                resourceParser.requireValidId(it.id)
                EventMembership(it.id, parseRole(it.role))
            }
        } catch (ex: ResourceValidationException) {
            log.structuredWarn(
                "Relation service returned invalid event id",
                ex,
                "event" to "relation_membership_response_invalid",
                "tenant_id" to tenantId,
                "subject" to userId,
                "failure_reason" to "relation_response_invalid",
            )
            throw RelationLookupException("relation_response_invalid")
        }
        log.structuredDebug(
            "Relation membership HTTP lookup completed",
            "event" to "relation_membership_http_lookup_completed",
            "tenant_id" to tenantId,
            "subject" to userId,
            "tenant_role" to tenantRole,
            "event_count" to events.size,
        )
        log.structuredTrace(
            "Relation membership HTTP lookup completed",
            "event" to "relation_membership_http_lookup_completed",
            "tenant_id" to tenantId,
            "subject" to userId,
            "event_count" to events.size,
        )
        return TenantMembership(tenantId, tenantRole, events)
    }

    private inline fun <reified T : Any> getOrNull(path: String, vararg variables: String): T? {
        return try {
            log.structuredDebug(
                "Relation API request started",
                "event" to "relation_api_request_started",
                "path" to path,
                "variable_count" to variables.size,
            )
            restClient.get()
                .uri(path, *variables)
                .retrieve()
                .onStatus({ it == HttpStatus.NOT_FOUND }) { _, _ -> throw RelationLookupException("tenant_not_found") }
                .body(T::class.java)
                .also {
                    log.structuredDebug(
                        "Relation API request completed",
                        "event" to "relation_api_request_completed",
                        "path" to path,
                        "response_present" to (it != null),
                        "result" to "success",
                    )
                }
        } catch (ex: RelationLookupException) {
            log.structuredDebug(
                "Relation API request returned known lookup failure",
                "event" to "relation_api_request_failed",
                "path" to path,
                "failure_reason" to ex.reason,
            )
            throw ex
        } catch (ex: RestClientException) {
            log.structuredWarn(
                "Relation API request failed",
                ex,
                "event" to "relation_api_request_failed",
                "path" to path,
                "failure_reason" to "relation_lookup_failed",
            )
            throw RelationLookupException("relation_lookup_failed")
        } catch (ex: RuntimeException) {
            log.structuredWarn(
                "Relation API response handling failed",
                ex,
                "event" to "relation_api_response_invalid",
                "path" to path,
                "failure_reason" to "relation_response_invalid",
            )
            throw RelationLookupException("relation_response_invalid")
        }
    }

    private fun parseRole(value: String): RelationRole {
        return try {
            RelationRole.fromExternal(value)
        } catch (ex: UnknownRelationRoleException) {
            log.structuredWarn(
                "Relation service returned unknown role",
                ex,
                "event" to "relation_role_unknown",
                "relation_role" to value,
                "failure_reason" to "relation_role_unknown",
            )
            throw RelationLookupException("relation_role_unknown")
        }
    }

    data class MembershipResponse(
        val tenant: TenantNode = TenantNode(),
        val user: UserNode = UserNode(),
        val events: List<EventNode> = emptyList(),
    )

    data class TenantNode(
        val id: String = "",
        val role: String? = null,
    )

    data class UserNode(
        val id: String = "",
    )

    data class EventNode(
        val id: String = "",
        val role: String = "",
    )

    companion object {
        private val log = LoggerFactory.getLogger(HttpRelationService::class.java)
    }
}
