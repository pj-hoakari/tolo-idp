package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditLogRepository
import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest
@AutoConfigureMockMvc
class DeviceAuthorizationFlowTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val jwtEncoder: JwtEncoder,
    @Autowired private val jwtDecoder: JwtDecoder,
    @Autowired private val jdbcClient: JdbcClient,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val auditLogRepository: AuditLogRepository,
) {
    @BeforeEach
    fun setUp() {
        jdbcClient.sql("DELETE FROM idp_device_grant_refresh_token").update()
        jdbcClient.sql("DELETE FROM idp_device_grant").update()
        jdbcClient.sql("DELETE FROM idp_revoked_edge_device").update()
        jdbcClient.sql("DELETE FROM idp_device_grant_lock").update()
        jdbcClient.sql("DELETE FROM oauth2_authorization").update()
        jdbcClient.sql("DELETE FROM idp_jti_denylist").update()
        auditLogRepository.deleteAll()
        cacheRepository.deleteAll()
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
                membership = TenantMembership(
                    tenantId = "tenant-a",
                    tenantRole = RelationRole.OWNER,
                    events = listOf(
                        EventMembership("event-1", RelationRole.OWNER),
                        EventMembership("event-staff", RelationRole.STAFF),
                    ),
                ),
                cachedAt = Instant.EPOCH,
                expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        )
    }

    @Test
    fun fullDeviceAuthorizationApprovalRefreshAndRevocationFlow() {
        val edgeDeviceId = "0123456789abcdef"
        val deviceCode = startDeviceAuthorization()
        poll(deviceCode).andExpect(status().isBadRequest).andExpect(jsonPath("$.error").value("authorization_pending"))

        val userCode = userCodeFor(deviceCode)
        approve(userCode, "event-1", edgeDeviceId)
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.edge_device_id").value(edgeDeviceId))

        val initial = poll(deviceCode)
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andExpect(jsonPath("$.scope").value("events.stream"))
            .andReturn()
        val initialJson = json(initial.response.contentAsString)
        val initialAccessToken = initialJson["access_token"].asText()
        val initialRefreshToken = initialJson["refresh_token"].asText()
        assertEventAccess(initialAccessToken, edgeDeviceId, "event-1")

        val refreshed = refresh(initialRefreshToken)
            .andExpect(status().isOk)
            .andReturn()
        val refreshedJson = json(refreshed.response.contentAsString)
        val refreshedAccessToken = refreshedJson["access_token"].asText()
        val refreshedRefreshToken = refreshedJson["refresh_token"].asText()
        assertNotEquals(initialRefreshToken, refreshedRefreshToken)
        assertEventAccess(refreshedAccessToken, edgeDeviceId, "event-1")

        refresh(initialRefreshToken)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
        assertTrue(grant(edgeDeviceId).revokedAt != null)

        refresh(refreshedRefreshToken)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        revoke("event-1", edgeDeviceId).andExpect(status().isNoContent)
        revoke("event-1", edgeDeviceId).andExpect(status().isNoContent)

        val nextDeviceCode = startDeviceAuthorization()
        approve(userCodeFor(nextDeviceCode), "event-1", edgeDeviceId)
            .andExpect(status().isBadRequest)
    }

    @Test
    fun refreshRotationRejectsReuseAndRevokesTheGrant() {
        val edgeDeviceId = "fedcba9876543210"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val firstRefresh = json(poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString)["refresh_token"].asText()

        val secondRefresh = json(refresh(firstRefresh).andExpect(status().isOk).andReturn().response.contentAsString)["refresh_token"].asText()
        assertNotEquals(firstRefresh, secondRefresh)

        refresh(firstRefresh)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
        assertNotNull(grant(edgeDeviceId).revokedAt)

        refresh(secondRefresh)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
    }

    @Test
    fun absoluteSevenDayCapLimitsRefreshAndAccessTokenExpiry() {
        val edgeDeviceId = "1111111111111111"
        val deviceCode = startDeviceAuthorization()
        val approveResult = approve(userCodeFor(deviceCode), "event-1", edgeDeviceId)
            .andExpect(status().isOk)
            .andReturn()
        val grantId = json(approveResult.response.contentAsString)["grant_id"].asText()
        val initial = poll(deviceCode).andExpect(status().isOk).andReturn()
        val initialJson = json(initial.response.contentAsString)
        val initialAccess = jwtDecoder.decode(initialJson["access_token"].asText())
        val grant = grant(edgeDeviceId)
        assertEquals(7 * 24 * 60 * 60L, ChronoUnit.SECONDS.between(grant.approvedAt, grant.absoluteExpiresAt))
        assertTrue(!initialAccess.expiresAt!!.isAfter(grant.absoluteExpiresAt))
        assertTrue(!refreshTokenExpiresAt(grantId).isAfter(grant.absoluteExpiresAt))

        val cappedAt = Instant.now().plusSeconds(120)
        jdbcClient.sql("UPDATE idp_device_grant SET absolute_expires_at = ? WHERE id = ?")
            .param(java.sql.Timestamp.from(cappedAt))
            .param(grantId)
            .update()

        val refreshed = refresh(initialJson["refresh_token"].asText())
            .andExpect(status().isOk)
            .andReturn()
        val refreshedJson = json(refreshed.response.contentAsString)
        val refreshedAccess = jwtDecoder.decode(refreshedJson["access_token"].asText())
        assertTrue(!refreshedAccess.expiresAt!!.isAfter(cappedAt))
        assertTrue(!refreshTokenExpiresAt(grantId).isAfter(cappedAt))

        jdbcClient.sql("UPDATE idp_device_grant SET absolute_expires_at = ? WHERE id = ?")
            .param(java.sql.Timestamp.from(Instant.now().minusSeconds(1)))
            .param(grantId)
            .update()
        refresh(refreshedJson["refresh_token"].asText())
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
    }

    @Test
    fun approvalRequiresVerifiedStaffEventRoleAndBffCredentials() {
        val edgeDeviceId = "2222222222222222"
        val userCode = userCodeFor(startDeviceAuthorization())
        val staffToken = staffToken()

        mockMvc.perform(
            post("/api/device-authorization/approve")
                .with(httpBasic("console-ui", "wrong-secret"))
                .header(STAFF_TOKEN_HEADER, staffToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(approvalBody(userCode, "event-1", edgeDeviceId)),
        )
            .andExpect(status().isUnauthorized)

        mockMvc.perform(
            post("/api/device-authorization/approve")
                .with(httpBasic("console-ui", "secret"))
                .header(STAFF_TOKEN_HEADER, staffToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(approvalBody(userCode, "event-3", edgeDeviceId)),
        )
            .andExpect(status().isForbidden)

        mockMvc.perform(
            post("/api/device-authorization/approve")
                .with(httpBasic("console-ui", "secret"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(approvalBody(userCode, "event-1", edgeDeviceId)),
        )
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun revokedEdgeRejectsApprovalAndRefresh() {
        val edgeDeviceId = "3333333333333333"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val refreshToken = json(poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString)["refresh_token"].asText()

        revoke("event-1", edgeDeviceId).andExpect(status().isNoContent)
        refresh(refreshToken)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        val nextDeviceCode = startDeviceAuthorization()
        approve(userCodeFor(nextDeviceCode), "event-1", edgeDeviceId)
            .andExpect(status().isBadRequest)
    }

    @Test
    fun concurrentRefreshesWithTheSameTokenSucceedOnceAndRevokeOnReuse() {
        val edgeDeviceId = "5555555555555555"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val refreshToken = json(
            poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString,
        )["refresh_token"].asText()

        val responses = performConcurrently(
            { refresh(refreshToken).andReturn().response },
            { refresh(refreshToken).andReturn().response },
        )

        assertEquals(
            1,
            responses.count { it.status == 200 },
            "exactly one concurrent refresh must succeed: ${responses.map { it.status }}",
        )
        val rejected = responses.single { it.status != 200 }
        assertEquals(400, rejected.status)
        assertEquals("invalid_grant", json(rejected.contentAsString)["error"].asText())
        assertNotNull(grant(edgeDeviceId).revokedAt)

        val winnerToken = json(responses.single { it.status == 200 }.contentAsString)["refresh_token"].asText()
        refresh(winnerToken)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
    }

    @Test
    fun refreshRacingWithRevocationLeavesTheDeviceRevoked() {
        val edgeDeviceId = "6666666666666666"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val refreshToken = json(
            poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString,
        )["refresh_token"].asText()

        val responses = performConcurrently(
            { refresh(refreshToken).andReturn().response },
            { revoke("event-1", edgeDeviceId).andReturn().response },
        )

        assertNotNull(grant(edgeDeviceId).revokedAt)
        assertEquals(204, responses[1].status)
        val refreshResponse = responses[0]
        if (refreshResponse.status == 200) {
            val rotated = json(refreshResponse.contentAsString)["refresh_token"].asText()
            refresh(rotated)
                .andExpect(status().isBadRequest)
                .andExpect(jsonPath("$.error").value("invalid_grant"))
        } else {
            assertEquals(400, refreshResponse.status)
            assertEquals("invalid_grant", json(refreshResponse.contentAsString)["error"].asText())
        }
    }

    @Test
    fun refreshPersistenceFailureRevokesTheGrantAndTheOldToken() {
        val edgeDeviceId = "7777777777777777"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val refreshToken = json(
            poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString,
        )["refresh_token"].asText()

        // Make the next refresh-token history insert fail without relying on application hooks.
        jdbcClient.sql(
            """
            ALTER TABLE idp_device_grant_refresh_token
            ADD COLUMN persistence_fault varchar(1) NOT NULL DEFAULT 'x'
            """.trimIndent(),
        ).update()
        jdbcClient.sql(
            "ALTER TABLE idp_device_grant_refresh_token ALTER COLUMN persistence_fault DROP DEFAULT",
        ).update()
        try {
            refresh(refreshToken)
                .andExpect(status().isBadRequest)
                .andExpect(jsonPath("$.error").value("server_error"))
        } finally {
            jdbcClient.sql("ALTER TABLE idp_device_grant_refresh_token DROP COLUMN persistence_fault").update()
        }
        assertNotNull(grant(edgeDeviceId).revokedAt)
        assertTrue(revocation(edgeDeviceId)?.permanent == false)

        refresh(refreshToken)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
    }

    @Test
    fun temporaryRevocationRequiresExplicitReapproval() {
        val edgeDeviceId = "8888888888888888"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val refreshToken = json(
            poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString,
        )["refresh_token"].asText()

        revoke("event-1", edgeDeviceId, permanent = false).andExpect(status().isNoContent)
        assertEquals(false, revocation(edgeDeviceId)?.permanent)
        refresh(refreshToken)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        val reapprovalCode = startDeviceAuthorization()
        val reapprovalUserCode = userCodeFor(reapprovalCode)
        approve(reapprovalUserCode, "event-1", edgeDeviceId)
            .andExpect(status().isBadRequest)
        approve(reapprovalUserCode, "event-1", edgeDeviceId, reapproval = true)
            .andExpect(status().isOk)
        assertNull(revocation(edgeDeviceId))
        poll(reapprovalCode).andExpect(status().isOk)
    }

    @Test
    fun permanentRevocationRejectsApprovalEvenWithReapproval() {
        val edgeDeviceId = "9999999999999999"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        poll(deviceCode).andExpect(status().isOk).andReturn()

        revoke("event-1", edgeDeviceId, permanent = true).andExpect(status().isNoContent)
        assertEquals(true, revocation(edgeDeviceId)?.permanent)

        // A later temporary revocation must not downgrade the permanent marker.
        revoke("event-1", edgeDeviceId, permanent = false).andExpect(status().isNoContent)
        assertEquals(true, revocation(edgeDeviceId)?.permanent)

        val nextCode = startDeviceAuthorization()
        approve(userCodeFor(nextCode), "event-1", edgeDeviceId, reapproval = true)
            .andExpect(status().isBadRequest)
    }

    @Test
    fun refreshTokenReuseRevocationCanBeClearedByExplicitReapproval() {
        val edgeDeviceId = "aaaaaaaaaaaaaaaa"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val firstRefresh = json(
            poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString,
        )["refresh_token"].asText()
        val rotated = json(refresh(firstRefresh).andExpect(status().isOk).andReturn().response.contentAsString)["refresh_token"].asText()

        refresh(firstRefresh)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
        assertNotNull(grant(edgeDeviceId).revokedAt)
        assertEquals(false, revocation(edgeDeviceId)?.permanent)

        refresh(rotated)
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        val reapprovalCode = startDeviceAuthorization()
        val reapprovalUserCode = userCodeFor(reapprovalCode)
        approve(reapprovalUserCode, "event-1", edgeDeviceId)
            .andExpect(status().isBadRequest)
        approve(reapprovalUserCode, "event-1", edgeDeviceId, reapproval = true)
            .andExpect(status().isOk)
        poll(reapprovalCode).andExpect(status().isOk)
    }

    @Test
    fun deviceAuthorizationRejectsCameraSuppliedEventAndEdgeBindings() {
        mockMvc.perform(
            post("/oauth2/device_authorization")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "esp-camera")
                .param("scope", "events.stream")
                .param("event_id", "event-1"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))

        mockMvc.perform(
            post("/oauth2/device_authorization")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "esp-camera")
                .param("scope", "events.stream")
                .param("edge_device_id", "0123456789abcdef"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
    }

    @Test
    fun introspectionExposesEdgeDeviceId() {
        val edgeDeviceId = "4444444444444444"
        val deviceCode = startDeviceAuthorization()
        approve(userCodeFor(deviceCode), "event-1", edgeDeviceId).andExpect(status().isOk)
        val accessToken = json(poll(deviceCode).andExpect(status().isOk).andReturn().response.contentAsString)["access_token"].asText()

        mockMvc.perform(
            post("/oauth2/introspect")
                .with(httpBasic("console-ui", "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("token", accessToken),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.token_use").value(TOKEN_USE_EVENT_ACCESS))
            .andExpect(jsonPath("$.edge_device_id").value(edgeDeviceId))
    }

    private fun startDeviceAuthorization(): String {
        val result = mockMvc.perform(
            post("/oauth2/device_authorization")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "esp-camera")
                .param("scope", "events.stream"),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.device_code").exists())
            .andExpect(jsonPath("$.user_code").exists())
            .andExpect(jsonPath("$.verification_uri").exists())
            .andExpect(jsonPath("$.expires_in").isNumber)
            .andExpect(jsonPath("$.interval").value(5))
            .andReturn()
        return json(result.response.contentAsString)["device_code"].asText()
    }

    private fun poll(deviceCode: String) =
        mockMvc.perform(
            post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "esp-camera")
                .param("grant_type", AuthorizationGrantType.DEVICE_CODE.value)
                .param("device_code", deviceCode),
        )

    private fun refresh(refreshToken: String) =
        mockMvc.perform(
            post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("client_id", "esp-camera")
                .param("grant_type", AuthorizationGrantType.REFRESH_TOKEN.value)
                .param("refresh_token", refreshToken),
        )

    private fun approve(
        userCode: String,
        eventId: String,
        edgeDeviceId: String,
        reapproval: Boolean? = null,
    ) =
        mockMvc.perform(
            post("/api/device-authorization/approve")
                .with(httpBasic("console-ui", "secret"))
                .header(STAFF_TOKEN_HEADER, staffToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(approvalBody(userCode, eventId, edgeDeviceId, reapproval)),
        )

    private fun revoke(eventId: String, edgeDeviceId: String, permanent: Boolean? = null) =
        mockMvc.perform(
            post("/api/device-authorization/revoke")
                .with(httpBasic("console-ui", "secret"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(revocationBody(eventId, edgeDeviceId, permanent)),
        )

    private fun performConcurrently(
        vararg requests: () -> MockHttpServletResponse,
    ): List<MockHttpServletResponse> {
        val executor = Executors.newFixedThreadPool(requests.size)
        val ready = CountDownLatch(requests.size)
        val start = CountDownLatch(1)
        return try {
            val futures = requests.map { request ->
                executor.submit(
                    Callable {
                        ready.countDown()
                        start.await(10, TimeUnit.SECONDS)
                        request()
                    },
                )
            }
            ready.await(10, TimeUnit.SECONDS)
            start.countDown()
            futures.map { it.get(30, TimeUnit.SECONDS) }
        } finally {
            executor.shutdownNow()
        }
    }

    private fun userCodeFor(deviceCode: String): String =
        jdbcClient.sql("SELECT user_code_value FROM oauth2_authorization WHERE device_code_value = ?")
            .param(deviceCode)
            .query(String::class.java)
            .single()

    private fun grant(edgeDeviceId: String): GrantRow =
        jdbcClient.sql(
            """
            SELECT approved_at, absolute_expires_at, revoked_at
            FROM idp_device_grant WHERE edge_device_id = ?
            ORDER BY created_at DESC
            """.trimIndent(),
        )
            .param(edgeDeviceId)
            .query { rs, _ ->
                GrantRow(
                    approvedAt = rs.getTimestamp("approved_at").toInstant(),
                    absoluteExpiresAt = rs.getTimestamp("absolute_expires_at").toInstant(),
                    revokedAt = rs.getTimestamp("revoked_at")?.toInstant(),
                )
            }
            .single()

    private fun revocation(edgeDeviceId: String): RevocationRow? =
        jdbcClient.sql(
            "SELECT permanent FROM idp_revoked_edge_device WHERE event_id = ? AND edge_device_id = ?",
        )
            .param("event-1")
            .param(edgeDeviceId)
            .query { rs, _ -> RevocationRow(rs.getBoolean("permanent")) }
            .optional()
            .orElse(null)

    private fun refreshTokenExpiresAt(grantId: String): Instant =
        jdbcClient.sql("SELECT refresh_token_expires_at FROM oauth2_authorization WHERE id = ?")
            .param(grantId)
            .query { rs, _ -> rs.getTimestamp("refresh_token_expires_at").toInstant() }
            .single()

    private fun assertEventAccess(accessToken: String, edgeDeviceId: String, eventId: String) {
        val jwt = jwtDecoder.decode(accessToken)
        assertEquals(IdpUserDetailsManager.DEVELOPMENT_USER_ID, jwt.subject)
        assertEquals("esp-camera", jwt.getClaimAsString("client_id"))
        assertEquals("events.stream", jwt.getClaimAsString("scope"))
        assertEquals(TOKEN_USE_EVENT_ACCESS, jwt.getClaimAsString("token_use"))
        assertEquals("tenant-a", jwt.getClaimAsString("tenant_id"))
        assertEquals(eventId, jwt.getClaimAsString("event_id"))
        assertEquals(edgeDeviceId, jwt.getClaimAsString("edge_device_id"))
        assertEquals(listOf("backend-api"), jwt.audience)
        assertTrue(!jwt.expiresAt!!.isAfter(Instant.now().plusSeconds(601)))
    }

    private fun staffToken(): String {
        val now = Instant.now()
        val claims = JwtClaimsSet.builder()
            .issuer("http://localhost:8080")
            .subject(IdpUserDetailsManager.DEVELOPMENT_USER_ID)
            .audience(listOf("backend-api"))
            .issuedAt(now)
            .notBefore(now)
            .expiresAt(now.plusSeconds(300))
            .claim("client_id", "console-ui")
            .claim("tenant_id", "tenant-a")
            .claim("token_use", TOKEN_USE_TENANT_ACCESS)
            .build()
        return jwtEncoder.encode(
            JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims),
        ).tokenValue
    }

    private fun approvalBody(
        userCode: String,
        eventId: String,
        edgeDeviceId: String,
        reapproval: Boolean? = null,
    ): String {
        val reapprovalField = reapproval?.let { ""","reapproval":$it""" }.orEmpty()
        return """{"user_code":"$userCode","event_id":"$eventId","edge_device_id":"$edgeDeviceId"$reapprovalField}"""
    }

    private fun revocationBody(eventId: String, edgeDeviceId: String, permanent: Boolean?): String {
        val permanentField = permanent?.let { ""","permanent":$it""" }.orEmpty()
        return """{"event_id":"$eventId","edge_device_id":"$edgeDeviceId"$permanentField}"""
    }

    private fun json(body: String) = tools.jackson.databind.json.JsonMapper.builder().build().readTree(body)

    private data class GrantRow(
        val approvedAt: Instant,
        val absoluteExpiresAt: Instant,
        val revokedAt: Instant?,
    )

    private data class RevocationRow(
        val permanent: Boolean,
    )
}
