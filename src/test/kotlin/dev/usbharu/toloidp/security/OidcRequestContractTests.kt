package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.json.JsonMapper
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:oidc-contract;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
@AutoConfigureMockMvc
class OidcRequestContractTests(
    @Autowired private val mvc: MockMvc,
    @Autowired private val cache: RelationMembershipCacheRepository,
    @Autowired private val json: JsonMapper,
    @Autowired private val decoder: JwtDecoder,
    @Autowired private val encoder: JwtEncoder,
    @Autowired private val denylist: JtiDenylistRepository,
    @Autowired private val authorizations: OAuth2AuthorizationService,
) {
    @BeforeEach
    fun membership() {
        cache.deleteAll()
        cache.save(RelationMembershipCache(
            cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
            membership = TenantMembership("tenant-a", RelationRole.OWNER, emptyList()),
            cachedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(300),
        ))
    }

    @ParameterizedTest
    @ValueSource(strings = ["", "none"])
    fun unauthenticatedRequestsReturnLoginRequiredToValidatedCallback(prompt: String) {
        val request = authorize()
        if (prompt.isNotEmpty()) request.queryParam("prompt", prompt)
        assertError(mvc.perform(request), "login_required")
    }

    @ParameterizedTest
    @ValueSource(strings = ["prompt", "max_age"])
    fun forcedReauthenticationRequiresNewLoginAndResumesOnlyOnce(parameter: String) {
        val session = login()
        fun request() = authorize(session).queryParam(parameter, if (parameter == "prompt") "login" else "0")
        assertError(mvc.perform(request()), "login_required")
        assertError(mvc.perform(request()), "login_required")
        mvc.perform(post("/api/login").session(session).contentType(MediaType.APPLICATION_JSON)
            .content("""{"username":"user-123","password":"wrong-password","tenantId":"tenant-a"}"""))
            .andExpect(status().isUnauthorized)
        assertError(mvc.perform(request()), "login_required")
        login(session)
        val tokens = exchange(mvc.perform(request()))
        val idToken = decoder.decode(tokens["id_token"].stringValue())
        assertEquals(authenticationTime(session), idToken.getClaimAsInstant("auth_time"))
        // Reusing a completed authorization request must not reuse the reauthentication proof.
        assertError(mvc.perform(request()), "login_required")
        val refreshed = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
            .param("grant_type", "refresh_token").param("refresh_token", tokens["refresh_token"].stringValue()))
            .andExpect(status().isOk).andReturn().response.contentAsString
        assertEquals(idToken.getClaimAsInstant("auth_time"), decoder.decode(json.readTree(refreshed)["id_token"].stringValue()).getClaimAsInstant("auth_time"))
    }

    @Test
    fun initialPromptLoginCanResumeAfterFrontendLoginWithoutTenantParameter() {
        val initial = mvc.perform(authorize().queryParam("prompt", "login"))
        assertError(initial, "login_required")
        val session = initial.andReturn().request.session as MockHttpSession
        login(session)
        exchange(mvc.perform(authorize(session).queryParam("prompt", "login")))
    }

    @Test
    fun changedRequestCannotReuseReauthenticationProof() {
        val session = login()
        assertError(mvc.perform(authorize(session).queryParam("prompt", "login")), "login_required")
        login(session)
        // Use a separate nonce to bind the challenge to the complete original request.
        assertError(mvc.perform(authorize(session).queryParam("prompt", "login").queryParam("nonce", "changed")), "login_required")
    }

    @Test
    fun expiredAuthenticationAgeRequiresFrontendLogin() {
        val session = login()
        val context = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) as SecurityContext
        val authentication = context.authentication as UsernamePasswordAuthenticationToken
        authentication.details = (authentication.details as Map<*, *>).entries.associate { it.key.toString() to it.value.toString() }
            .toMutableMap().apply { put("auth_time", Instant.now().minusSeconds(60).epochSecond.toString()) }
        assertError(mvc.perform(authorize(session).queryParam("max_age", "30")), "login_required")
        login(session)
        val tokens = exchange(mvc.perform(authorize(session).queryParam("max_age", "30")))
        assertEquals(authenticationTime(session), decoder.decode(tokens["id_token"].stringValue()).getClaimAsInstant("auth_time"))
    }

    @ParameterizedTest
    @ValueSource(strings = ["-1", "1.0", " 1", "9223372036854775808", ""])
    fun invalidMaxAgeIsRejected(value: String) {
        assertError(mvc.perform(authorize(login()).queryParam("max_age", value)), "invalid_request")
    }

    @Test
    fun silentRequestDoesNotSatisfyForcedReauthenticationAndRejectsConflictingPrompts() {
        val session = login()
        assertError(mvc.perform(authorize(session).queryParam("prompt", "none").queryParam("max_age", "0")), "login_required")
        assertError(mvc.perform(authorize(session).queryParam("prompt", "none login")), "invalid_request")
        assertError(mvc.perform(authorize(session).queryParam("max_age", "1", "2")), "invalid_request")
    }

    @ParameterizedTest
    @ValueSource(strings = ["nonce-with-symbols_123-ABC", " ", " nonce with spaces "])
    fun nonceIsReturnedUnmodifiedInIdToken(nonce: String) {
        val tokens = exchange(mvc.perform(authorize(login()).queryParam("nonce", nonce)))
        assertEquals(nonce, decoder.decode(tokens["id_token"].stringValue()).getClaimAsString("nonce"))
    }

    @Test
    fun duplicateNonceIsRejectedBeforeIssuingAuthorizationCode() {
        val session = login()
        assertError(mvc.perform(authorize(session).queryParam("nonce", "first", "second")), "invalid_request")
        assertError(mvc.perform(authorize(session).queryParam("nonce", "same", "same")), "invalid_request")
    }

    @Test
    fun emptyNonceIsTreatedAsOmitted() {
        val tokens = exchange(mvc.perform(authorize(login()).queryParam("nonce", "")))
        assertNull(decoder.decode(tokens["id_token"].stringValue()).getClaimAsString("nonce"))
    }

    @Test
    fun unsupportedInteractivePromptsNeverSilentlyIssueCode() {
        val session = login()
        assertError(mvc.perform(authorize(session).queryParam("prompt", "consent")), "consent_required")
        assertError(mvc.perform(authorize(session).queryParam("prompt", "select_account")), "account_selection_required")
        assertError(mvc.perform(authorize(session).queryParam("prompt", "unknown")), "invalid_request")
        // A completed login challenge does not prove consent or account selection.
        assertError(mvc.perform(authorize(session).queryParam("prompt", "login consent")), "login_required")
        login(session)
        assertError(mvc.perform(authorize(session).queryParam("prompt", "login consent")), "consent_required")
    }

    @Test
    fun unsupportedRequestObjectIsRejectedInsteadOfIgnoringItsClaims() {
        assertError(mvc.perform(authorize(login()).queryParam("request", "unsupported-request-object")), "request_not_supported")
        mvc.perform(authorize(clientId = "unknown-client").queryParam("request", "unsupported-request-object"))
            .andExpect(status().isBadRequest).andExpect(header().doesNotExist("Location"))
    }

    @Test
    fun unsupportedRequestUriReturnsOidcErrorOnlyToTrustedRedirect() {
        assertError(mvc.perform(authorize(login()).queryParam("request_uri", "https://rp.invalid/request.jwt")), "request_uri_not_supported")
        mvc.perform(authorize(login(), redirectUri = "https://attacker.invalid/callback")
            .queryParam("request_uri", "https://rp.invalid/request.jwt"))
            .andExpect(status().isBadRequest).andExpect(header().doesNotExist("Location"))
    }

    @ParameterizedTest
    @ValueSource(strings = ["fragment", "form_post", "unknown", ""])
    fun unsupportedResponseModeCannotSilentlyFallBackToQuery(value: String) {
        assertError(mvc.perform(authorize(login()).queryParam("response_mode", value)), "invalid_request")
    }

    @Test
    fun queryResponseModeIsSupportedButMustNotBeRepeated() {
        exchange(mvc.perform(authorize(login()).queryParam("response_mode", "query")))
        assertError(mvc.perform(authorize(login()).queryParam("response_mode", "query", "query")), "invalid_request")
    }

    @Test
    fun hintsRequireValidSignatureIssuerAudienceAndMatchingSubject() {
        val session = login()
        exchange(mvc.perform(authorize(session).queryParam("id_token_hint", signedHint())))
        // An expired ID Token remains a valid hint, rather than a bearer credential.
        exchange(mvc.perform(authorize(session).queryParam("id_token_hint", signedHint(expiry = Instant.now().minusSeconds(60)))))
        for (invalid in listOf("not-a-jwt", signedHint(issuer = "https://foreign.invalid"), signedHint(audience = "another-client"))) {
            assertError(mvc.perform(authorize(session).queryParam("id_token_hint", invalid)), "invalid_request")
        }
        val valid = signedHint()
        val tampered = valid.split('.').let { "${it[0]}.${it[1]}.AAAA" }
        assertError(mvc.perform(authorize(session).queryParam("id_token_hint", tampered)), "invalid_request")
        assertError(mvc.perform(authorize(session).queryParam("id_token_hint", signedHint(subject = UUID.randomUUID().toString()))), "login_required")
    }

    @Test
    fun invalidRedirectAndUnknownClientNeverRedirect() {
        mvc.perform(authorize(clientId = "unknown-client"))
            .andExpect(status().isBadRequest).andExpect(header().doesNotExist("Location"))
        mvc.perform(get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", "client-123")
            .queryParam("redirect_uri", "https://attacker.invalid/callback").queryParam("scope", "openid"))
            .andExpect(status().isBadRequest).andExpect(header().doesNotExist("Location"))
    }

    @Test
    fun scopeAndMembershipErrorsReturnToClientWithState() {
        val session = login()
        cache.deleteAll()
        cache.save(RelationMembershipCache(cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
            membership = TenantMembership("tenant-a", RelationRole.STAFF, emptyList()),
            cachedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(300)))
        assertError(mvc.perform(authorize(session, "openid tenant.write")), "invalid_scope")
    }

    @Test
    fun previousJwtCanBeRevokedAfterRefreshWithoutRevokingCurrentToken() {
        val tokens = exchange(mvc.perform(authorize(login())))
        val old = tokens["access_token"].stringValue()
        val oldJwt = decoder.decode(old)
        val refreshed = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
            .param("grant_type", "refresh_token").param("refresh_token", tokens["refresh_token"].stringValue()))
            .andExpect(status().isOk).andReturn().response.contentAsString
        val current = json.readTree(refreshed)["access_token"].stringValue()
        assertNull(authorizations.findByToken(old, OAuth2TokenType.ACCESS_TOKEN))
        repeat(2) { revoke(old).andExpect(status().isOk).andExpect(content().string("")) }
        assertTrue(denylist.existsById(oldJwt.id!!))
        assertEquals(oldJwt.expiresAt, denylist.findById(oldJwt.id!!).get().expiresAt)
        assertFalse(denylist.existsById(decoder.decode(current).id!!))
        mvc.perform(post("/oauth2/introspect").with(httpBasic("service-gateway", "gateway-secret")).param("token", current))
            .andExpect(status().isOk).andExpect(jsonPath("$.active").value(true))
    }

    @Test
    fun unstoredJwtRevocationRejectsWrongClientAndIgnoresInvalidTokens() {
        val entries = denylist.count()
        val foreignClient = signedAccessToken(clientId = "another-client")
        revoke(foreignClient).andExpect(status().isBadRequest).andExpect(jsonPath("$.error").value("invalid_client"))
        assertFalse(denylist.existsById(decoder.decode(foreignClient).id!!))
        for (token in listOf("unknown-token", signedHint(), signedAccessToken(issuer = "https://foreign.invalid"),
            signedAccessToken(expiry = Instant.now().minusSeconds(120)), signedAccessToken(notBefore = Instant.now().plusSeconds(120)))) {
            revoke(token).andExpect(status().isOk).andExpect(content().string(""))
        }
        assertEquals(entries, denylist.count())
    }

    private fun signedHint(
        subject: String = IdpUserDetailsManager.DEVELOPMENT_USER_ID, issuer: String = ISSUER,
        audience: String = "client-123", expiry: Instant = Instant.now().plusSeconds(300),
    ): String = sign(JwtClaimsSet.builder().issuer(issuer).subject(subject).audience(listOf(audience))
        .issuedAt(Instant.now().minusSeconds(3600)).expiresAt(expiry).build())

    private fun signedAccessToken(
        clientId: String = "client-123", issuer: String = ISSUER,
        expiry: Instant = Instant.now().plusSeconds(300), notBefore: Instant = Instant.now().minusSeconds(300),
    ): String = sign(JwtClaimsSet.builder().issuer(issuer).subject(IdpUserDetailsManager.DEVELOPMENT_USER_ID)
        .audience(listOf("backend-api")).issuedAt(Instant.now().minusSeconds(300)).notBefore(notBefore)
        .expiresAt(expiry).id(UUID.randomUUID().toString()).claim("token_use", "tenant_access").claim("client_id", clientId).build())

    private fun sign(claims: JwtClaimsSet): String = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).tokenValue
    private fun revoke(token: String) = mvc.perform(post("/oauth2/revoke").with(httpBasic("client-123", "secret")).param("token", token))
    private fun authenticationTime(session: MockHttpSession): Instant {
        val context = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) as SecurityContext
        return Instant.ofEpochSecond(OidcAuthenticationRequestValidator.authenticationTime(context.authentication!!)!!)
    }
    private fun login(session: MockHttpSession? = null): MockHttpSession {
        val request = post("/api/login").contentType(MediaType.APPLICATION_JSON)
            .content("""{"username":"user-123","password":"password","tenantId":"tenant-a"}""")
        if (session != null) request.session(session)
        return mvc.perform(request).andExpect(status().isOk).andReturn().request.session as MockHttpSession
    }
    private fun authorize(session: MockHttpSession? = null, scope: String = "openid tenant.read", clientId: String = "client-123", redirectUri: String = REDIRECT): MockHttpServletRequestBuilder {
        val request = get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri).queryParam("scope", scope).queryParam("state", "request-state")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").queryParam("code_challenge_method", "S256")
        if (session != null) request.session(session)
        return request
    }
    private fun assertError(result: ResultActions, error: String) {
        val location = result.andExpect(status().isFound).andReturn().response.redirectedUrl!!
        assertTrue(location.startsWith("$REDIRECT?"))
        val parameters = UriComponentsBuilder.fromUriString(location).build().queryParams
        assertEquals(error, parameters.getFirst("error"))
        assertNull(parameters.getFirst("code"))
        assertEquals("request-state", parameters.getFirst("state"))
    }
    private fun exchange(result: ResultActions): tools.jackson.databind.JsonNode {
        val location = result.andExpect(status().isFound).andReturn().response.redirectedUrl!!
        val code = UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code")!!
        val response = mvc.perform(post("/oauth2/token").with(httpBasic("client-123", "secret"))
            .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", REDIRECT)
            .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
            .andExpect(status().isOk).andReturn().response.contentAsString
        return json.readTree(response)
    }
    companion object {
        private const val REDIRECT = "http://127.0.0.1:8080/login/oauth2/code/client-123"
        private const val ISSUER = "http://localhost:8080"
    }
}
