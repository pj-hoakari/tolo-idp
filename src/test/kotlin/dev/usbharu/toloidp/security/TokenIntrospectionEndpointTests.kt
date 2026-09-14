package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AccessToken
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
import java.time.Duration
import java.time.Instant
import java.util.UUID

@SpringBootTest
@AutoConfigureMockMvc
class TokenIntrospectionEndpointTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val authorizationService: OAuth2AuthorizationService,
    @Autowired private val registeredClientRepository: RegisteredClientRepository,
    @Autowired private val passwordEncoder: PasswordEncoder,
    @Autowired private val clientPolicyRepository: ClientPolicyRepository,
    @Autowired private val jdbcClient: JdbcClient,
) {
    @BeforeEach
    fun setUp() {
        jdbcClient.sql("delete from oauth2_authorization").update()
        ensurePublicPolicyClient()
    }

    @Test
    fun confidentialClientCanIntrospectActiveTenantAccessTokenUsingClientSecretPost() {
        val tokenValue = "tenant-token-post-${UUID.randomUUID()}"
        saveAuthorization(
            tokenValue = tokenValue,
            claims = tokenClaims(
                tokenUse = TOKEN_USE_TENANT_ACCESS,
                resource = "https://api.example.com/tenants/tenant-1",
                tenantId = "tenant-1",
            ),
        )

        mockMvc.perform(introspectionRequest("client-123", "secret", tokenValue, useClientSecretPost = true))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.client_id").value("client-123"))
            .andExpect(jsonPath("$.token_use").value(TOKEN_USE_TENANT_ACCESS))
            .andExpect(content().string(not(containsString(tokenValue))))
            .andExpect(content().string(not(containsString("secret"))))
    }

    @Test
    fun confidentialClientCanIntrospectActiveTenantAccessToken() {
        val tokenValue = "tenant-token-${UUID.randomUUID()}"
        saveAuthorization(
            tokenValue = tokenValue,
            claims = tokenClaims(
                tokenUse = TOKEN_USE_TENANT_ACCESS,
                resource = "https://api.example.com/tenants/tenant-1",
                tenantId = "tenant-1",
            ),
        )

        mockMvc.perform(introspectionRequest("client-123", "secret", tokenValue))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.client_id").value("client-123"))
            .andExpect(jsonPath("$.scope").value("tenant.read events.read"))
            .andExpect(jsonPath("$.aud[0]").value("backend-api"))
            .andExpect(jsonPath("$.iss").value("http://localhost:8080"))
            .andExpect(jsonPath("$.sub").value("user-123"))
            .andExpect(jsonPath("$.jti").value("jti-tenant_access"))
            .andExpect(jsonPath("$.token_use").value(TOKEN_USE_TENANT_ACCESS))
            .andExpect(jsonPath("$.resource").value("https://api.example.com/tenants/tenant-1"))
            .andExpect(jsonPath("$.tenant_id").value("tenant-1"))
            .andExpect(jsonPath("$.role").doesNotExist())
            .andExpect(jsonPath("$.tenant_role").doesNotExist())
            .andExpect(jsonPath("$.event_role").doesNotExist())
            .andExpect(content().string(not(containsString(tokenValue))))
            .andExpect(content().string(not(containsString("secret"))))
    }

    @Test
    fun confidentialClientCanIntrospectActiveEventAccessToken() {
        val tokenValue = "event-token-${UUID.randomUUID()}"
        saveAuthorization(
            tokenValue = tokenValue,
            claims = tokenClaims(
                tokenUse = TOKEN_USE_EVENT_ACCESS,
                resource = "https://api.example.com/tenants/tenant-1/events/event-1",
                tenantId = "tenant-1",
                eventId = "event-1",
            ),
        )

        mockMvc.perform(introspectionRequest("client-123", "secret", tokenValue))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.client_id").value("client-123"))
            .andExpect(jsonPath("$.token_use").value(TOKEN_USE_EVENT_ACCESS))
            .andExpect(jsonPath("$.tenant_id").value("tenant-1"))
            .andExpect(jsonPath("$.event_id").value("event-1"))
            .andExpect(jsonPath("$.role").doesNotExist())
            .andExpect(jsonPath("$.tenant_role").doesNotExist())
            .andExpect(jsonPath("$.event_role").doesNotExist())
            .andExpect(content().string(not(containsString(tokenValue))))
    }

    @Test
    fun introspectionDoesNotExposeRoleClaimsEvenIfStoredWithToken() {
        val tokenValue = "role-claim-token-${UUID.randomUUID()}"
        saveAuthorization(
            tokenValue = tokenValue,
            claims = tokenClaims(includeForbiddenRoleClaims = true),
        )

        mockMvc.perform(introspectionRequest("client-123", "secret", tokenValue))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.role").doesNotExist())
            .andExpect(jsonPath("$.tenant_role").doesNotExist())
            .andExpect(jsonPath("$.event_role").doesNotExist())
            .andExpect(content().string(not(containsString("owner"))))
            .andExpect(content().string(not(containsString(tokenValue))))
            .andExpect(content().string(not(containsString("secret"))))
    }

    @Test
    fun missingExpiredAndRevokedTokensReturnInactive() {
        val expiredToken = "expired-token-${UUID.randomUUID()}"
        val revokedToken = "revoked-token-${UUID.randomUUID()}"

        saveAuthorization(tokenValue = expiredToken, expiresAt = Instant.now().minusSeconds(60))
        saveAuthorization(tokenValue = revokedToken, invalidated = true)

        mockMvc.perform(introspectionRequest("client-123", "secret", "missing-token"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(false))
            .andExpect(jsonPath("$.error").doesNotExist())
            .andExpect(jsonPath("$.client_id").doesNotExist())
            .andExpect(jsonPath("$.token_use").doesNotExist())
            .andExpect(content().string(not(containsString("missing-token"))))

        mockMvc.perform(introspectionRequest("client-123", "secret", expiredToken))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(false))
            .andExpect(jsonPath("$.error").doesNotExist())
            .andExpect(jsonPath("$.client_id").doesNotExist())
            .andExpect(jsonPath("$.token_use").doesNotExist())
            .andExpect(content().string(not(containsString(expiredToken))))

        mockMvc.perform(introspectionRequest("client-123", "secret", revokedToken))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(false))
            .andExpect(jsonPath("$.error").doesNotExist())
            .andExpect(jsonPath("$.client_id").doesNotExist())
            .andExpect(jsonPath("$.token_use").doesNotExist())
            .andExpect(content().string(not(containsString(revokedToken))))
    }

    @Test
    fun publicPolicyClientCanIntrospectTokens() {
        val tokenValue = "public-accepted-token-${UUID.randomUUID()}"
        saveAuthorization(tokenValue = tokenValue)

        mockMvc.perform(introspectionRequest(PUBLIC_POLICY_CLIENT_ID, PUBLIC_POLICY_CLIENT_SECRET, tokenValue))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.client_id").value("client-123"))
            .andExpect(content().string(not(containsString(tokenValue))))
    }

    @Test
    fun invalidTokenParametersAreRejected() {
        mockMvc.perform(
            post("/oauth2/introspect")
                .with(httpBasic("client-123", "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
            .andExpect(jsonPath("$.error_description").doesNotExist())
            .andExpect(content().string(not(containsString("secret"))))

        mockMvc.perform(
            post("/oauth2/introspect")
                .with(httpBasic("client-123", "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("token", ""),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
            .andExpect(jsonPath("$.error_description").doesNotExist())
            .andExpect(content().string(not(containsString("secret"))))

        mockMvc.perform(
            post("/oauth2/introspect")
                .with(httpBasic("client-123", "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("token", "one", "two"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
            .andExpect(jsonPath("$.error_description").doesNotExist())
            .andExpect(content().string(not(containsString("one"))))
            .andExpect(content().string(not(containsString("two"))))
            .andExpect(content().string(not(containsString("secret"))))
    }

    @Test
    fun invalidTokenTypeHintParametersAreRejectedWithoutLeakingInputs() {
        val tokenValue = "hint-token-${UUID.randomUUID()}"

        mockMvc.perform(
            introspectionRequest("client-123", "secret", tokenValue)
                .param("token_type_hint", "access_token", "refresh_token"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
            .andExpect(jsonPath("$.error_description").doesNotExist())
            .andExpect(content().string(not(containsString(tokenValue))))
            .andExpect(content().string(not(containsString("secret"))))
    }

    private fun introspectionRequest(
        clientId: String,
        clientSecret: String,
        tokenValue: String,
        useClientSecretPost: Boolean = false,
    ) =
        post("/oauth2/introspect")
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
            .param("token", tokenValue)

    private fun saveAuthorization(
        tokenValue: String,
        claims: Map<String, Any> = tokenClaims(),
        expiresAt: Instant = Instant.now().plusSeconds(3600),
        invalidated: Boolean = false,
    ) {
        val registeredClient = registeredClientRepository.findByClientId("client-123")
            ?: error("seed client-123 is required")
        val issuedAt = expiresAt.minusSeconds(3600)
        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            tokenValue,
            issuedAt,
            expiresAt,
            setOf("tenant.read", "events.read"),
        )
        val authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName("user-123")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(setOf("tenant.read", "events.read"))
            .token(accessToken) { metadata ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = claims
                if (invalidated) {
                    metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = true
                }
            }
            .build()
        authorizationService.save(authorization)
    }

    private fun tokenClaims(
        tokenUse: String = TOKEN_USE_TENANT_ACCESS,
        resource: String = "https://api.example.com/tenants/tenant-1",
        tenantId: String = "tenant-1",
        eventId: String? = null,
        includeForbiddenRoleClaims: Boolean = false,
    ): Map<String, Any> {
        val claims = linkedMapOf<String, Any>(
            "iss" to "http://localhost:8080",
            "sub" to "user-123",
            "aud" to listOf("backend-api"),
            "client_id" to "client-123",
            "scope" to listOf("tenant.read", "events.read"),
            "token_use" to tokenUse,
            "resource" to resource,
            "iat" to Instant.parse("2026-01-01T00:00:00Z"),
            "nbf" to Instant.parse("2026-01-01T00:00:00Z"),
            "exp" to Instant.parse("2030-01-01T00:00:00Z"),
            "jti" to "jti-$tokenUse",
            "tenant_id" to tenantId,
        )
        if (eventId != null) {
            claims["event_id"] = eventId
        }
        if (includeForbiddenRoleClaims) {
            claims["role"] = "owner"
            claims["tenant_role"] = "owner"
            claims["event_role"] = "staff"
        }
        return claims
    }

    private fun ensurePublicPolicyClient() {
        if (registeredClientRepository.findByClientId(PUBLIC_POLICY_CLIENT_ID) == null) {
            registeredClientRepository.save(
                RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(PUBLIC_POLICY_CLIENT_ID)
                    .clientSecret(passwordEncoder.encode(PUBLIC_POLICY_CLIENT_SECRET))
                    .clientName("Public policy test client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/public-policy")
                    .scope("tenant.read")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .build(),
            )
        }

        clientPolicyRepository.deleteById(PUBLIC_POLICY_CLIENT_ID)
        clientPolicyRepository.save(
            ClientPolicy(
                clientId = PUBLIC_POLICY_CLIENT_ID,
                clientType = ClientType.PUBLIC,
                allowedGrantTypes = setOf(AuthorizationGrantType.AUTHORIZATION_CODE.value),
                allowedTransitions = emptySet(),
                allowedAudiences = setOf("backend-api"),
                allowedScopes = setOf("tenant.read"),
                tenantAccessTtl = Duration.ofSeconds(900),
                eventAccessTtl = Duration.ofSeconds(600),
            ),
        )
    }

    private companion object {
        const val PUBLIC_POLICY_CLIENT_ID = "public-introspection-client"
        const val PUBLIC_POLICY_CLIENT_SECRET = "public-secret"
    }
}
