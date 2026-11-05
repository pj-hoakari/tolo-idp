package dev.usbharu.toloidp.audit

import org.slf4j.LoggerFactory
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional
import tools.jackson.databind.ObjectMapper
import java.time.Clock
import java.time.Instant

/**
 * トークン発行・交換に関する監査イベントを永続化し、監査ログへ出力するサービス。
 *
 * OAuth2 の外部エラーレスポンスへ出さない成功・失敗理由を、内部監査用の記録として保持する。
 */
@Service
class AuditService(
    private val repository: AuditLogRepository,
    private val objectMapper: ObjectMapper,
    private val clock: Clock,
) {
    private val logger = LoggerFactory.getLogger("audit.token")

    /**
     * トークン監査イベントを独立したトランザクションで保存し、同じ構造化ペイロードを監査ロガーへ出力する。
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    fun record(event: TokenAuditEvent) {
        val timestamp = Instant.now(clock)
        val payload = objectMapper.writeValueAsString(event.toPayload(timestamp))
        logger.info(payload)
        repository.save(
            AuditLogRecord(
                timestamp = timestamp,
                requestId = bounded(event.requestId, REQUEST_ID_MAX),
                clientId = bounded(event.clientId, CLIENT_ID_MAX),
                subject = bounded(event.subject, SUBJECT_MAX),
                sourceTokenUse = bounded(event.sourceTokenUse, SOURCE_TOKEN_USE_MAX),
                requestedTokenUse = bounded(event.requestedTokenUse, REQUESTED_TOKEN_USE_MAX),
                requestedAudience = bounded(event.requestedAudience, REQUESTED_AUDIENCE_MAX),
                requestedResource = bounded(event.requestedResource, REQUESTED_RESOURCE_MAX),
                requestedScope = boundedText(event.requestedScope.joinToString(" "), REQUESTED_SCOPE_MAX),
                issuedScope = boundedText(event.issuedScope.joinToString(" "), ISSUED_SCOPE_MAX),
                tenantId = bounded(event.tenantId, TENANT_ID_MAX),
                eventId = bounded(event.eventId, EVENT_ID_MAX),
                result = boundedText(event.result, RESULT_MAX),
                failureReason = bounded(event.failureReason, FAILURE_REASON_MAX),
                sourceIp = bounded(event.sourceIp, SOURCE_IP_MAX),
                userAgent = bounded(event.userAgent, USER_AGENT_MAX),
                issuedJti = bounded(event.issuedJti, ISSUED_JTI_MAX),
                payload = payload,
            ),
        )
    }

    private fun bounded(value: String?, maxLength: Int): String? =
        if (value == null || value.length <= maxLength) {
            value
        } else {
            value.take(maxLength - TRUNCATION_MARKER.length) + TRUNCATION_MARKER
        }

    private fun boundedText(value: String, maxLength: Int): String =
        if (value.length <= maxLength) {
            value
        } else {
            value.take(maxLength - TRUNCATION_MARKER.length) + TRUNCATION_MARKER
        }

    private fun TokenAuditEvent.toPayload(timestamp: Instant): Map<String, Any?> =
        linkedMapOf(
            "timestamp" to timestamp.toString(),
            "requestId" to requestId,
            "clientId" to clientId,
            "subject" to subject,
            "sourceTokenUse" to sourceTokenUse,
            "requestedTokenUse" to requestedTokenUse,
            "requestedAudience" to requestedAudience,
            "requestedResource" to requestedResource,
            "requestedScope" to ArrayList(requestedScope),
            "issuedScope" to ArrayList(issuedScope),
            "tenantId" to tenantId,
            "eventId" to eventId,
            "result" to result,
            "failureReason" to failureReason,
            "sourceIp" to sourceIp,
            "userAgent" to userAgent,
            "issuedJti" to issuedJti,
        )

    private companion object {
        private const val TRUNCATION_MARKER = "...[truncated]"
        private const val REQUEST_ID_MAX = 200
        private const val CLIENT_ID_MAX = 100
        private const val SUBJECT_MAX = 200
        private const val SOURCE_TOKEN_USE_MAX = 50
        private const val REQUESTED_TOKEN_USE_MAX = 50
        private const val REQUESTED_AUDIENCE_MAX = 200
        private const val REQUESTED_RESOURCE_MAX = 1000
        private const val REQUESTED_SCOPE_MAX = 1000
        private const val ISSUED_SCOPE_MAX = 1000
        private const val TENANT_ID_MAX = 100
        private const val EVENT_ID_MAX = 100
        private const val RESULT_MAX = 20
        private const val FAILURE_REASON_MAX = 100
        private const val SOURCE_IP_MAX = 100
        private const val USER_AGENT_MAX = 500
        private const val ISSUED_JTI_MAX = 100
    }
}

@Table("idp_audit_log")
data class AuditLogRecord(
    @Id
    @Column("id")
    val id: Long? = null,
    @Column("timestamp")
    val timestamp: Instant,
    @Column("request_id")
    val requestId: String?,
    @Column("client_id")
    val clientId: String?,
    @Column("subject")
    val subject: String?,
    @Column("source_token_use")
    val sourceTokenUse: String?,
    @Column("requested_token_use")
    val requestedTokenUse: String?,
    @Column("requested_audience")
    val requestedAudience: String?,
    @Column("requested_resource")
    val requestedResource: String?,
    @Column("requested_scope")
    val requestedScope: String,
    @Column("issued_scope")
    val issuedScope: String,
    @Column("tenant_id")
    val tenantId: String?,
    @Column("event_id")
    val eventId: String?,
    @Column("result")
    val result: String,
    @Column("failure_reason")
    val failureReason: String?,
    @Column("source_ip")
    val sourceIp: String?,
    @Column("user_agent")
    val userAgent: String?,
    @Column("issued_jti")
    val issuedJti: String?,
    @Column("payload")
    val payload: String,
)

interface AuditLogRepository : CrudRepository<AuditLogRecord, Long>

data class TokenAuditEvent(
    val timestamp: String? = null,
    val requestId: String? = null,
    val clientId: String? = null,
    val subject: String? = null,
    val sourceTokenUse: String? = null,
    val requestedTokenUse: String? = null,
    val requestedAudience: String? = null,
    val requestedResource: String? = null,
    val requestedScope: List<String> = emptyList(),
    val issuedScope: List<String> = emptyList(),
    val tenantId: String? = null,
    val eventId: String? = null,
    val result: String,
    val failureReason: String? = null,
    val sourceIp: String? = null,
    val userAgent: String? = null,
    val issuedJti: String? = null,
)
