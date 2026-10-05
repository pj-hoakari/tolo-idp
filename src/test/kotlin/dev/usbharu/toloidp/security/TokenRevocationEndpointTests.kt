package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditLogRepository
import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Principal
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@SpringBootTest
@AutoConfigureMockMvc
class TokenRevocationEndpointTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val authorizationService: OAuth2AuthorizationService,
    @Autowired private val registeredClientRepository: RegisteredClientRepository,
    @Autowired private val passwordEncoder: PasswordEncoder,
    @Autowired private val clientPolicyRepository: ClientPolicyRepository,
    @Autowired private val jtiDenylistRepository: JtiDenylistRepository,
    @Autowired private val auditLogRepository: AuditLogRepository,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val jdbcClient: JdbcClient,
) {
    @BeforeEach
    fun setUp() {
        jdbcClient.sql("delete from oauth2_authorization").update()
        auditLogRepository.deleteAll()
        jtiDenylistRepository.deleteAll()
        cacheRepository.deleteAll()
        ensureClient(
            clientId = "client-123",
            clientSecret = "secret",
            clientType = ClientType.CONFIDENTIAL,
        )
        ensureClient(
            clientId = PUBLIC_POLICY_CLIENT_ID,
            clientSecret = PUBLIC_POLICY_CLIENT_SECRET,
            clientType = ClientType.PUBLIC,
        )
        ensureClient(
            clientId = OTHER_CONFIDENTIAL_CLIENT_ID,
            clientSecret = OTHER_CONFIDENTIAL_CLIENT_SECRET,
            clientType = ClientType.CONFIDENTIAL,
        )
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
                membership = TenantMembership(
                    tenantId = "tenant-a",
                    tenantRole = RelationRole.OWNER,
                    events = listOf(EventMembership("event-1", RelationRole.OWNER)),
                ),
                cachedAt = Instant.EPOCH,
                expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        )
    }

    @Test
    fun revokesTenantAccessTokenUsingClientSecretPostAuthentication() {
        val token = saveAuthorization(jti = "tenant-revoke-post-jti")

        mockMvc.perform(revocationRequest(token, useClientSecretPost = true))
            .andExpect(status().isOk)
            .andExpect(content().string(""))

        assertTrue(jtiDenylistRepository.existsById("tenant-revoke-post-jti"))
    }

    @Test
    fun revokesTenantAccessTokenByAddingJtiToDenylistAndRecordingAudit() {
        val expiresAt = Instant.now().plusSeconds(3600)
        val token = saveAuthorization(jti = "tenant-revoke-jti", expiresAt = expiresAt)

        mockMvc.perform(revocationRequest(token))
            .andExpect(status().isOk)
            .andExpect(content().string(""))

        val entry = jtiDenylistRepository.findById("tenant-revoke-jti").orElseThrow()
        assertEquals(expiresAt.epochSecond, entry.expiresAt.epochSecond)
        val audit = latestAudit()
        assertEquals("success", audit.result)
        assertEquals("client-123", audit.clientId)
        assertEquals("user-123", audit.subject)
        assertEquals(TOKEN_USE_TENANT_ACCESS, audit.sourceTokenUse)
        assertEquals("revocation", audit.requestedTokenUse)
        assertEquals("tenant-revoke-jti", audit.issuedJti)
        assertFalse(audit.payload.contains(token))
    }

    @Test
    fun revokesEventAccessTokenByAddingJtiToDenylist() {
        val token = saveAuthorization(
            tokenUse = TOKEN_USE_EVENT_ACCESS,
            resource = "https://api.example.com/tenants/tenant-a/events/event-1",
            eventId = "event-1",
            jti = "event-revoke-jti",
        )

        mockMvc.perform(revocationRequest(token))
            .andExpect(status().isOk)

        assertTrue(jtiDenylistRepository.existsById("event-revoke-jti"))
        assertEquals(TOKEN_USE_EVENT_ACCESS, latestAudit().sourceTokenUse)
    }

    @Test
    fun revokedTokenCannotBeUsedAsTokenExchangeSubject() {
        val token = saveAuthorization(jti = "exchange-denied-by-revoke")

        mockMvc.perform(revocationRequest(token))
            .andExpect(status().isOk)

        mockMvc.perform(tokenExchangeRequest(token))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        assertEquals("token_revoked", latestAudit().failureReason)
    }

    @Test
    fun unknownExpiredAndAlreadyDeniedTokensReturnOkWithoutLeakingToken() {
        val unknownToken = "unknown-${UUID.randomUUID()}"
        val expiredToken = saveAuthorization(
            jti = "expired-revoke-jti",
            expiresAt = Instant.now().minusSeconds(60),
        )
        val deniedToken = saveAuthorization(jti = "already-denied-jti")
        jtiDenylistRepository.save(
            JtiDenylistEntry("already-denied-jti", Instant.now().plusSeconds(3600))
                .apply { isNewEntity = true },
        )

        mockMvc.perform(revocationRequest(unknownToken))
            .andExpect(status().isOk)
            .andExpect(content().string(not(containsString(unknownToken))))
        mockMvc.perform(revocationRequest(expiredToken))
            .andExpect(status().isOk)
            .andExpect(content().string(not(containsString(expiredToken))))
        mockMvc.perform(revocationRequest(deniedToken))
            .andExpect(status().isOk)
            .andExpect(content().string(not(containsString(deniedToken))))

        assertFalse(jtiDenylistRepository.existsById("expired-revoke-jti"))
        assertTrue(jtiDenylistRepository.existsById("already-denied-jti"))
    }

    @Test
    fun rejectsTokenIssuedToDifferentClientWithoutDenylistRegistration() {
        val token = saveAuthorization(jti = "other-client-denied-jti")

        mockMvc.perform(
            revocationRequest(
                token = token,
                clientId = OTHER_CONFIDENTIAL_CLIENT_ID,
                clientSecret = OTHER_CONFIDENTIAL_CLIENT_SECRET,
            ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_client"))
            .andExpect(content().string(not(containsString(token))))

        assertFalse(jtiDenylistRepository.existsById("other-client-denied-jti"))
        assertEquals("subject_token_client_mismatch", latestAudit().failureReason)
    }

    @Test
    fun rejectsPublicPolicyClientWithoutDenylistRegistration() {
        val token = saveAuthorization(jti = "public-client-denied-jti", clientId = PUBLIC_POLICY_CLIENT_ID)

        mockMvc.perform(
            revocationRequest(
                token = token,
                clientId = PUBLIC_POLICY_CLIENT_ID,
                clientSecret = PUBLIC_POLICY_CLIENT_SECRET,
            ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_client"))

        assertFalse(jtiDenylistRepository.existsById("public-client-denied-jti"))
        assertEquals("client_not_allowed", latestAudit().failureReason)
    }

    @Test
    fun rejectsUnsupportedTokenTypeHint() {
        val token = saveAuthorization(jti = "unsupported-hint-jti")

        mockMvc.perform(
            revocationRequest(token)
                .param(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2ParameterNames.REFRESH_TOKEN),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("unsupported_token_type"))
            .andExpect(content().string(not(containsString(token))))

        assertFalse(jtiDenylistRepository.existsById("unsupported-hint-jti"))
        assertEquals("unsupported_token_type", latestAudit().failureReason)
    }

    private fun revocationRequest(
        token: String,
        clientId: String = "client-123",
        clientSecret: String = "secret",
        useClientSecretPost: Boolean = false,
    ) =
        post("/oauth2/revoke")
            .apply {
                if (useClientSecretPost) {
                    contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    param("client_id", clientId)
                    param("client_secret", clientSecret)
                } else {
                    with(httpBasic(clientId, clientSecret))
                    contentType(MediaType.APPLICATION_FORM_URLENCODED)
                }
            }
            .param(OAuth2ParameterNames.TOKEN, token)

    private fun tokenExchangeRequest(token: String) =
        post("/oauth2/token")
            .with(httpBasic("client-123", "secret"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("grant_type", AuthorizationGrantType.TOKEN_EXCHANGE.value)
            .param("subject_token_type", ACCESS_TOKEN_TYPE)
            .param("subject_token", token)
            .param("audience", "backend-api")
            .param("resource", "https://api.example.com/tenants/tenant-a/events/event-1")
            .param("scope", "events.read")

    private fun saveAuthorization(
        tokenUse: String = TOKEN_USE_TENANT_ACCESS,
        clientId: String = "client-123",
        resource: String = "https://api.example.com/tenants/tenant-a",
        tenantId: String = "tenant-a",
        eventId: String? = null,
        jti: String = "jti-${UUID.randomUUID()}",
        expiresAt: Instant = Instant.now().plusSeconds(3600),
    ): String {
        val tokenValue = "revocation-token-${UUID.randomUUID()}"
        val registeredClient = registeredClientRepository.findByClientId(clientId)
            ?: error("client $clientId is required")
        val authentication = UsernamePasswordAuthenticationToken.authenticated(
            "user-123",
            null,
            listOf(SimpleGrantedAuthority("ROLE_USER")),
        )
        val issuedAt = expiresAt.minusSeconds(3600)
        val scopes = setOf("tenant.read", "events.read", "events.manage")
        val token = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            tokenValue,
            issuedAt,
            expiresAt,
            scopes,
        )
        val authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName("user-123")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(scopes)
            .attribute(Principal::class.java.name, authentication)
            .token(token) { metadata ->
                val claims = linkedMapOf<String, Any>(
                    "iss" to "http://localhost:8080",
                    "sub" to "user-123",
                    "aud" to listOf("backend-api"),
                    "client_id" to clientId,
                    "scope" to scopes.joinToString(" "),
                    "token_use" to tokenUse,
                    "resource" to resource,
                    "tenant_id" to tenantId,
                    "iat" to issuedAt,
                    "nbf" to issuedAt,
                    "exp" to expiresAt,
                    "jti" to jti,
                )
                if (eventId != null) {
                    claims["event_id"] = eventId
                }
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = claims
            }
            .build()
        authorizationService.save(authorization)
        return tokenValue
    }

    private fun ensureClient(
        clientId: String,
        clientSecret: String,
        clientType: ClientType,
    ) {
        if (registeredClientRepository.findByClientId(clientId) == null) {
            registeredClientRepository.save(
                RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientId)
                    .clientSecret(passwordEncoder.encode(clientSecret))
                    .clientName("$clientId revocation test client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/$clientId")
                    .scope("tenant.read")
                    .scope("events.read")
                    .scope("events.manage")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .build(),
            )
        }
        clientPolicyRepository.deleteById(clientId)
        clientPolicyRepository.save(
            ClientPolicy(
                clientId = clientId,
                clientType = clientType,
                allowedGrantTypes = setOf(
                    AuthorizationGrantType.AUTHORIZATION_CODE.value,
                    AuthorizationGrantType.TOKEN_EXCHANGE.value,
                ),
                allowedTransitions = setOf(TOKEN_EXCHANGE_TRANSITION_TENANT_TO_EVENT),
                allowedAudiences = setOf("backend-api"),
                allowedScopes = setOf("tenant.read", "events.read", "events.manage"),
                tenantAccessTtl = Duration.ofSeconds(900),
                eventAccessTtl = Duration.ofSeconds(600),
            ),
        )
    }

    private fun latestAudit() =
        auditLogRepository.findAll().maxBy { it.id ?: 0 }

    private companion object {
        const val PUBLIC_POLICY_CLIENT_ID = "public-revocation-client"
        const val PUBLIC_POLICY_CLIENT_SECRET = "public-secret"
        const val OTHER_CONFIDENTIAL_CLIENT_ID = "other-revocation-client"
        const val OTHER_CONFIDENTIAL_CLIENT_SECRET = "other-secret"
    }
}
