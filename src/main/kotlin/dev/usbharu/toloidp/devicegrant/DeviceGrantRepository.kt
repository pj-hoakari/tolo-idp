package dev.usbharu.toloidp.devicegrant

import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.stereotype.Repository
import java.sql.Timestamp
import java.time.Instant
import javax.sql.DataSource

@Repository
class DeviceGrantRepository(
    private val jdbc: JdbcClient,
    private val dataSource: DataSource,
) {
    private val postgres by lazy {
        dataSource.connection.use { connection ->
            connection.metaData.databaseProductName.contains("PostgreSQL", ignoreCase = true)
        }
    }

    fun findById(id: String): DeviceGrant? =
        jdbc.sql("$SELECT_GRANT WHERE id = :id")
            .param("id", id)
            .query(::mapGrant)
            .optional()
            .orElse(null)

    fun findActiveByEventAndEdge(eventId: String, edgeDeviceId: String): DeviceGrant? =
        jdbc.sql("$SELECT_GRANT WHERE event_id = :event_id AND edge_device_id = :edge_device_id AND revoked_at IS NULL")
            .param("event_id", eventId)
            .param("edge_device_id", edgeDeviceId)
            .query(::mapGrant)
            .optional()
            .orElse(null)

    fun findUnrevokedByEventAndEdge(eventId: String, edgeDeviceId: String): List<DeviceGrant> =
        jdbc.sql("$SELECT_GRANT WHERE event_id = :event_id AND edge_device_id = :edge_device_id AND revoked_at IS NULL")
            .param("event_id", eventId)
            .param("edge_device_id", edgeDeviceId)
            .query(::mapGrant)
            .list()

    fun insert(grant: DeviceGrant) {
        jdbc.sql(
            """
            INSERT INTO idp_device_grant (
                id, tenant_id, event_id, edge_device_id, approver_sub, client_id,
                approved_at, absolute_expires_at, revoked_at, revoked_reason, created_at
            ) VALUES (
                :id, :tenant_id, :event_id, :edge_device_id, :approver_sub, :client_id,
                :approved_at, :absolute_expires_at, :revoked_at, :revoked_reason, :created_at
            )
            """.trimIndent(),
        )
            .param("id", grant.id)
            .param("tenant_id", grant.tenantId)
            .param("event_id", grant.eventId)
            .param("edge_device_id", grant.edgeDeviceId)
            .param("approver_sub", grant.approverSubject)
            .param("client_id", grant.clientId)
            .param("approved_at", Timestamp.from(grant.approvedAt))
            .param("absolute_expires_at", Timestamp.from(grant.absoluteExpiresAt))
            .param("revoked_at", grant.revokedAt?.let(Timestamp::from))
            .param("revoked_reason", grant.revokedReason)
            .param("created_at", Timestamp.from(grant.createdAt))
            .update()
    }

    fun markRevoked(id: String, revokedAt: Instant, reason: String): Int =
        jdbc.sql(
            """
            UPDATE idp_device_grant
            SET revoked_at = :revoked_at, revoked_reason = :reason
            WHERE id = :id AND revoked_at IS NULL
            """.trimIndent(),
        )
            .param("revoked_at", Timestamp.from(revokedAt))
            .param("reason", reason)
            .param("id", id)
            .update()

    fun markRevokedForEventAndEdge(eventId: String, edgeDeviceId: String, revokedAt: Instant, reason: String): Int =
        jdbc.sql(
            """
            UPDATE idp_device_grant
            SET revoked_at = :revoked_at, revoked_reason = :reason
            WHERE event_id = :event_id AND edge_device_id = :edge_device_id AND revoked_at IS NULL
            """.trimIndent(),
        )
            .param("revoked_at", Timestamp.from(revokedAt))
            .param("reason", reason)
            .param("event_id", eventId)
            .param("edge_device_id", edgeDeviceId)
            .update()

    fun isRevoked(eventId: String, edgeDeviceId: String): Boolean =
        findRevocation(eventId, edgeDeviceId) != null

    fun findRevocation(eventId: String, edgeDeviceId: String): EdgeDeviceRevocation? =
        jdbc.sql(
            """
            SELECT event_id, edge_device_id, revoked_at, permanent
            FROM idp_revoked_edge_device
            WHERE event_id = :event_id AND edge_device_id = :edge_device_id
            """.trimIndent(),
        )
            .param("event_id", eventId)
            .param("edge_device_id", edgeDeviceId)
            .query { rs, _ ->
                EdgeDeviceRevocation(
                    eventId = rs.getString("event_id"),
                    edgeDeviceId = rs.getString("edge_device_id"),
                    revokedAt = rs.getTimestamp("revoked_at").toInstant(),
                    permanent = rs.getBoolean("permanent"),
                )
            }
            .optional()
            .orElse(null)

    /**
     * Records a permanent or temporary edge-device revocation.
     *
     * A permanent revocation is sticky: a later temporary revocation never makes the edge
     * reapprovable again.
     */
    fun markEdgeDeviceRevoked(
        eventId: String,
        edgeDeviceId: String,
        revokedAt: Instant,
        permanent: Boolean,
    ) {
        val updated = jdbc.sql(
            """
            UPDATE idp_revoked_edge_device
            SET revoked_at = :revoked_at,
                permanent = CASE WHEN permanent THEN TRUE ELSE :permanent END
            WHERE event_id = :event_id AND edge_device_id = :edge_device_id
            """.trimIndent(),
        )
            .param("revoked_at", Timestamp.from(revokedAt))
            .param("permanent", permanent)
            .param("event_id", eventId)
            .param("edge_device_id", edgeDeviceId)
            .update()
        if (updated > 0) {
            return
        }
        if (postgres) {
            jdbc.sql(
                """
                INSERT INTO idp_revoked_edge_device (event_id, edge_device_id, revoked_at, permanent)
                VALUES (:event_id, :edge_device_id, :revoked_at, :permanent)
                ON CONFLICT (event_id, edge_device_id) DO NOTHING
                """.trimIndent(),
            )
                .param("event_id", eventId)
                .param("edge_device_id", edgeDeviceId)
                .param("revoked_at", Timestamp.from(revokedAt))
                .param("permanent", permanent)
                .update()
        } else {
            jdbc.sql(
                """
                MERGE INTO idp_revoked_edge_device (event_id, edge_device_id, revoked_at, permanent)
                KEY (event_id, edge_device_id)
                VALUES (:event_id, :edge_device_id, :revoked_at, :permanent)
                """.trimIndent(),
            )
                .param("event_id", eventId)
                .param("edge_device_id", edgeDeviceId)
                .param("revoked_at", Timestamp.from(revokedAt))
                .param("permanent", permanent)
                .update()
        }
    }

    /**
     * Clears only a temporary revocation. A permanently revoked edge stays revoked.
     */
    fun clearTemporaryRevocation(eventId: String, edgeDeviceId: String): Int =
        jdbc.sql(
            """
            DELETE FROM idp_revoked_edge_device
            WHERE event_id = :event_id AND edge_device_id = :edge_device_id AND permanent = FALSE
            """.trimIndent(),
        )
            .param("event_id", eventId)
            .param("edge_device_id", edgeDeviceId)
            .update()

    fun lockEdgeDevice(edgeDeviceId: String) {
        if (postgres) {
            jdbc.sql("INSERT INTO idp_device_grant_lock (edge_device_id) VALUES (:edge_device_id) ON CONFLICT DO NOTHING")
                .param("edge_device_id", edgeDeviceId)
                .update()
        } else {
            jdbc.sql(
                "MERGE INTO idp_device_grant_lock (edge_device_id) KEY (edge_device_id) VALUES (:edge_device_id)",
            )
                .param("edge_device_id", edgeDeviceId)
                .update()
        }
        jdbc.sql("SELECT edge_device_id FROM idp_device_grant_lock WHERE edge_device_id = :edge_device_id FOR UPDATE")
            .param("edge_device_id", edgeDeviceId)
            .query(String::class.java)
            .single()
    }

    fun insertRefreshToken(token: DeviceGrantRefreshToken) {
        jdbc.sql(
            """
            INSERT INTO idp_device_grant_refresh_token (token_hash, grant_id, issued_at, expires_at, superseded_at)
            VALUES (:token_hash, :grant_id, :issued_at, :expires_at, :superseded_at)
            """.trimIndent(),
        )
            .param("token_hash", token.tokenHash)
            .param("grant_id", token.grantId)
            .param("issued_at", Timestamp.from(token.issuedAt))
            .param("expires_at", Timestamp.from(token.expiresAt))
            .param("superseded_at", token.supersededAt?.let(Timestamp::from))
            .update()
    }

    fun findRefreshToken(tokenHash: String): DeviceGrantRefreshToken? =
        jdbc.sql(
            """
            SELECT token_hash, grant_id, issued_at, expires_at, superseded_at
            FROM idp_device_grant_refresh_token
            WHERE token_hash = :token_hash
            """.trimIndent(),
        )
            .param("token_hash", tokenHash)
            .query(::mapRefreshToken)
            .optional()
            .orElse(null)

    fun supersedeRefreshToken(grantId: String, tokenHash: String, supersededAt: Instant): Int =
        jdbc.sql(
            """
            UPDATE idp_device_grant_refresh_token
            SET superseded_at = :superseded_at
            WHERE grant_id = :grant_id AND token_hash = :token_hash AND superseded_at IS NULL
            """.trimIndent(),
        )
            .param("superseded_at", Timestamp.from(supersededAt))
            .param("grant_id", grantId)
            .param("token_hash", tokenHash)
            .update()

    private fun mapGrant(rs: java.sql.ResultSet, rowNum: Int): DeviceGrant =
        DeviceGrant(
            id = rs.getString("id"),
            tenantId = rs.getString("tenant_id"),
            eventId = rs.getString("event_id"),
            edgeDeviceId = rs.getString("edge_device_id"),
            approverSubject = rs.getString("approver_sub"),
            clientId = rs.getString("client_id"),
            approvedAt = rs.getTimestamp("approved_at").toInstant(),
            absoluteExpiresAt = rs.getTimestamp("absolute_expires_at").toInstant(),
            revokedAt = rs.getTimestamp("revoked_at")?.toInstant(),
            revokedReason = rs.getString("revoked_reason"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
        )

    private fun mapRefreshToken(rs: java.sql.ResultSet, rowNum: Int): DeviceGrantRefreshToken =
        DeviceGrantRefreshToken(
            tokenHash = rs.getString("token_hash"),
            grantId = rs.getString("grant_id"),
            issuedAt = rs.getTimestamp("issued_at").toInstant(),
            expiresAt = rs.getTimestamp("expires_at").toInstant(),
            supersededAt = rs.getTimestamp("superseded_at")?.toInstant(),
        )

    private companion object {
        const val SELECT_GRANT = """
            SELECT id, tenant_id, event_id, edge_device_id, approver_sub, client_id,
                   approved_at, absolute_expires_at, revoked_at, revoked_reason, created_at
            FROM idp_device_grant
        """
    }
}
