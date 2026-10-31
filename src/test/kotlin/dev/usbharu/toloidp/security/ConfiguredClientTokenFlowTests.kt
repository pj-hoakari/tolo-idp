package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.user.IdpUserDetailsManager
import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.oauth2.jwt.JwtDecoder
import tools.jackson.core.type.TypeReference
import tools.jackson.databind.ObjectMapper
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertFalse

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "server.address=127.0.0.1",
        "server.servlet.session.cookie.secure=false",
        "spring.datasource.url=jdbc:h2:mem:configured-client-flow;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.client-id=configured-web-client",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.client-secret=dummy-web-secret",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.client-authentication-methods=client_secret_basic",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.authorization-grant-types=authorization_code,refresh_token,urn:ietf:params:oauth:grant-type:token-exchange",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.redirect-uris=https://example.invalid/callback",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.scopes=openid,tenant.read,tenant.write,events.read",
        "spring.security.oauth2.authorizationserver.client.web-app.require-proof-key=true",
        "spring.security.oauth2.authorizationserver.client.web-app.token.reuse-refresh-tokens=false",
        "spring.security.oauth2.authorizationserver.client.web-app.token.refresh-token-time-to-live=1h",
        "tolo-idp.clients.web-app.allowed-audiences=configured-api",
        "tolo-idp.clients.web-app.allowed-token-exchange-transitions=tenant_access:event_access",
        "tolo-idp.clients.web-app.tenant-access-ttl=123s",
        "tolo-idp.clients.web-app.event-access-ttl=45s",
    ],
)
class ConfiguredClientTokenFlowTests(
    @LocalServerPort private val port: Int,
    @Autowired private val memberships: RelationMembershipCacheRepository,
    @Autowired private val decoder: JwtDecoder,
    @Autowired private val mapper: ObjectMapper,
    @Autowired private val jdbc: JdbcTemplate,
) {
    @Test
    fun configurationAloneEnablesAuthorizationCodeAndTokenExchangeWithConfiguredAudienceAndTtls() {
        memberships.deleteAll()
        memberships.save(RelationMembershipCache(
            cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
            membership = TenantMembership("tenant-a", RelationRole.OWNER, listOf(EventMembership("event-1", RelationRole.OWNER))),
            cachedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(300),
        ))
        HttpClient.newBuilder().cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ALL)).build().use { http ->
            try {
                val redirect = "https://example.invalid/callback"
                val query = form(mapOf(
                    "response_type" to "code", "client_id" to "configured-web-client", "redirect_uri" to redirect,
                    "scope" to "openid tenant.read events.read", "audience" to "configured-api",
                    "resource" to "https://api.example.com/tenants/tenant-a",
                    "state" to "fixture-state", "nonce" to "fixture-nonce",
                    "code_challenge" to "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method" to "S256",
                ))
                val authorize = authorize(http, query)
                assertEquals(302, authorize.statusCode())
                val location = URI.create(authorize.headers().firstValue("Location").orElseThrow())
                val parameters = location.rawQuery.split('&').associate { entry ->
                    val pair = entry.split('=', limit = 2)
                    pair[0] to URLDecoder.decode(pair[1], Charsets.UTF_8)
                }
                assertEquals("fixture-state", parameters["state"])
                val tokens = send(http, "/oauth2/token", form(mapOf(
                    "grant_type" to "authorization_code", "code" to parameters.getValue("code"), "redirect_uri" to redirect,
                    "code_verifier" to "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                )), authenticate = true)
                assertEquals(200, tokens.statusCode())
                val tenantToken = json(tokens).getValue("access_token") as String
                val tenant = decoder.decode(tenantToken)
                assertEquals(IdpUserDetailsManager.DEVELOPMENT_USER_ID, tenant.subject)
                assertEquals(IdpUserDetailsManager.DEVELOPMENT_USER_ID, decoder.decode(json(tokens).getValue("id_token") as String).subject)
                assertEquals(listOf("configured-api"), tenant.audience)
                assertEquals(123, Duration.between(tenant.issuedAt, tenant.expiresAt).seconds.toInt())
                assertEquals("tenant_access", tenant.claims["token_use"])
                val exchange = send(http, "/oauth2/token", form(mapOf(
                    "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token" to tenantToken, "subject_token_type" to "urn:ietf:params:oauth:token-type:access_token",
                    "audience" to "configured-api", "resource" to "https://api.example.com/tenants/tenant-a/events/event-1",
                    "scope" to "events.read",
                )), authenticate = true)
                assertEquals(200, exchange.statusCode())
                val eventToken = json(exchange).getValue("access_token") as String
                val event = decoder.decode(eventToken)
                assertEquals(tenant.subject, event.subject)
                assertEquals(listOf("configured-api"), event.audience)
                assertEquals(45, Duration.between(event.issuedAt, event.expiresAt).seconds.toInt())
                assertEquals("event_access", event.claims["token_use"])
                val introspection = send(http, "/oauth2/introspect", form(mapOf("token" to eventToken)), authenticate = true)
                assertEquals(200, introspection.statusCode())
                assertEquals(true, json(introspection)["active"])
                assertEquals(0, jdbc.queryForObject(
                    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE LOWER(TABLE_NAME) = 'idp_client_policy'", Int::class.java,
                ))
            } finally {
                send(http, "/api/logout", "")
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = [false, true])
    fun refreshRotatesWithoutSessionAndPreservesTenantClaims(oidc: Boolean) {
        seedMembership(RelationRole.OWNER)
        val http = HttpClient.newBuilder().cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ALL)).build()
        http.use {
            val scope = if (oidc) "openid tenant.read events.read" else "tenant.read events.read"
            val initial = issueTokens(http, scope)
            val original = decoder.decode(initial.getValue("access_token") as String)
            val refresh = initial.getValue("refresh_token") as String
            assertEquals(oidc, initial.containsKey("id_token"))
            assertEquals(204, send(http, "/api/logout", "").statusCode())
            val expanded = refresh(http, refresh, "tenant.write")
            assertEquals(400, expanded.statusCode())
            assertEquals("invalid_scope", json(expanded)["error"])
            val wrongClient = send(http, "/oauth2/token", form(mapOf("grant_type" to "refresh_token", "refresh_token" to refresh)),
                basicCredentials = "client-123:secret")
            assertEquals(400, wrongClient.statusCode())
            assertEquals("invalid_grant", json(wrongClient)["error"])
            val updated = refresh(http, refresh)
            assertEquals(200, updated.statusCode())
            val tokens = json(updated)
            val rotated = tokens.getValue("refresh_token") as String
            assertNotEquals(refresh, rotated)
            assertEquals(oidc, tokens.containsKey("id_token"))
            if (oidc) {
                val idToken = decoder.decode(tokens.getValue("id_token") as String)
                assertEquals(original.subject, idToken.subject)
                assertEquals(listOf("configured-web-client"), idToken.audience)
            }
            val access = decoder.decode(tokens.getValue("access_token") as String)
            for (claim in listOf("sub", "aud", "client_id", "token_use", "tenant_id", "resource")) {
                assertEquals(original.claims[claim], access.claims[claim], claim)
            }
            assertNotEquals(original.id, access.id)
            assertEquals(123, Duration.between(access.issuedAt, access.expiresAt).seconds.toInt())
            assertEquals(scope.split(" ").toSet(), (tokens["scope"] as String).split(" ").toSet())
            for (claim in listOf("role", "tenant_role", "event_role", "event_id")) assertFalse(access.hasClaim(claim))
            val reused = refresh(http, refresh)
            assertEquals(400, reused.statusCode())
            assertEquals("invalid_grant", json(reused)["error"])
            val narrowed = refresh(http, rotated, "tenant.read")
            assertEquals(200, narrowed.statusCode())
            assertEquals("tenant.read", json(narrowed)["scope"])
            val next = json(narrowed).getValue("refresh_token") as String
            // Check actual expiry handling without waiting an hour.
            jdbc.update("UPDATE oauth2_authorization SET refresh_token_issued_at = ?, refresh_token_expires_at = ? WHERE registered_client_id = ?",
                java.sql.Timestamp.from(Instant.now().minusSeconds(7200)),
                java.sql.Timestamp.from(Instant.now().minusSeconds(10)), "web-app")
            val expired = refresh(http, next)
            assertEquals(400, expired.statusCode())
            assertEquals("invalid_grant", json(expired)["error"])
        }
    }

    @Test
    fun refreshRechecksCurrentRoleRatherThanReusingPreviouslyGrantedScopes() {
        seedMembership(RelationRole.OWNER)
        HttpClient.newBuilder().cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ALL)).build().use { http ->
            val initial = issueTokens(http, "tenant.write")
            try {
                seedMembership(RelationRole.STAFF)
                val rejected = refresh(http, initial.getValue("refresh_token") as String)
                assertEquals(400, rejected.statusCode())
                assertEquals("invalid_scope", json(rejected)["error"])
            } finally {
                send(http, "/api/logout", "")
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["refresh_token", "access_token", ""])
    fun revokedRefreshTokenCannotRefreshOrExchangeAndIntrospectionIsInactive(hint: String) {
        seedMembership(RelationRole.OWNER)
        HttpClient.newBuilder().cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ALL)).build().use { http ->
            val initial = issueTokens(http, "openid tenant.read events.read")
            try {
                val refresh = initial.getValue("refresh_token") as String
                // Revoke the current token after rotation, rather than just the initial token.
                val refreshed = refresh(http, refresh)
                assertEquals(200, refreshed.statusCode())
                val current = json(refreshed)
                val currentRefresh = current.getValue("refresh_token") as String
                val access = current.getValue("access_token") as String
                val params = mutableMapOf("token" to currentRefresh)
                if (hint.isNotEmpty()) params["token_type_hint"] = hint
                val revoked = send(http, "/oauth2/revoke", form(params), authenticate = true)
                assertEquals(200, revoked.statusCode())
                assertEquals("", revoked.body())
                val rejected = refresh(http, currentRefresh)
                assertEquals(400, rejected.statusCode())
                assertEquals("invalid_grant", json(rejected)["error"])
                for (token in listOf(currentRefresh, access)) {
                    val introspection = send(http, "/oauth2/introspect", form(mapOf("token" to token)), authenticate = true)
                    assertEquals(200, introspection.statusCode())
                    assertEquals(mapOf("active" to false), json(introspection))
                }
                val exchange = send(http, "/oauth2/token", form(mapOf(
                    "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token" to access, "subject_token_type" to "urn:ietf:params:oauth:token-type:access_token",
                    "audience" to "configured-api", "resource" to "https://api.example.com/tenants/tenant-a/events/event-1",
                    "scope" to "events.read",
                )), authenticate = true)
                assertEquals(400, exchange.statusCode())
                assertEquals("invalid_grant", json(exchange)["error"])
            } finally {
                send(http, "/api/logout", "")
            }
        }
    }

    @Test
    fun loginFailureStatusesSurviveTheServletErrorDispatch() {
        seedMembership(RelationRole.OWNER)
        HttpClient.newBuilder().cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ALL)).build().use { http ->
            val unknown = send(http, "/api/login", body = """{"username":"user-123","password":"password","challenge":"unknown"}""", contentType = "application/json")
            assertEquals(400, unknown.statusCode())
            val query = form(mapOf(
                "response_type" to "code", "client_id" to "configured-web-client", "redirect_uri" to "https://example.invalid/callback",
                "scope" to "openid tenant.read", "audience" to "configured-api", "resource" to "https://api.example.com/tenants/tenant-a",
                "code_challenge" to "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method" to "S256",
            ))
            val challenge = loginChallenge(send(http, "/oauth2/authorize?$query").headers().firstValue("Location").orElseThrow())
            val wrong = send(http, "/api/login", body = """{"username":"user-123","password":"wrong","challenge":"$challenge"}""", contentType = "application/json")
            assertEquals(401, wrong.statusCode())
            memberships.deleteAll()
            val forbidden = send(http, "/api/login", body = """{"username":"user-123","password":"password","challenge":"$challenge"}""", contentType = "application/json")
            assertEquals(403, forbidden.statusCode())
        }
    }

    private fun seedMembership(role: RelationRole) {
        memberships.deleteAll()
        memberships.save(RelationMembershipCache(
            cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
            membership = TenantMembership("tenant-a", role, listOf(EventMembership("event-1", RelationRole.OWNER))),
            cachedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(300),
        ))
    }

    private fun issueTokens(http: HttpClient, scope: String): Map<String, Any> {
        val redirect = "https://example.invalid/callback"
        val query = form(mapOf(
            "response_type" to "code", "client_id" to "configured-web-client", "redirect_uri" to redirect,
            "scope" to scope, "audience" to "configured-api", "nonce" to "refresh-test-nonce",
            "resource" to "https://api.example.com/tenants/tenant-a",
            "code_challenge" to "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method" to "S256",
        ))
        val authorize = authorize(http, query)
        assertEquals(302, authorize.statusCode())
        val location = URI.create(authorize.headers().firstValue("Location").orElseThrow())
        val params = location.rawQuery.split('&').associate {
            val pair = it.split('=', limit = 2)
            pair[0] to URLDecoder.decode(pair[1], Charsets.UTF_8)
        }
        val response = send(http, "/oauth2/token", form(mapOf(
            "grant_type" to "authorization_code", "code" to params.getValue("code"), "redirect_uri" to redirect,
            "code_verifier" to "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        )), authenticate = true)
        assertEquals(200, response.statusCode())
        return json(response)
    }

    private fun authorize(http: HttpClient, query: String): HttpResponse<String> {
        val challenged = send(http, "/oauth2/authorize?$query")
        assertEquals(302, challenged.statusCode())
        val challenge = loginChallenge(challenged.headers().firstValue("Location").orElseThrow())
        val login = send(http, "/api/login", body = """{"username":"user-123","password":"password","challenge":"$challenge"}""", contentType = "application/json")
        assertEquals(200, login.statusCode())
        return send(http, "/oauth2/authorize?challenge=$challenge")
    }

    private fun refresh(http: HttpClient, token: String, scope: String? = null): HttpResponse<String> {
        val params = mutableMapOf("grant_type" to "refresh_token", "refresh_token" to token)
        if (scope != null) params["scope"] = scope
        return send(http, "/oauth2/token", form(params), authenticate = true)
    }

    private fun send(http: HttpClient, path: String, body: String? = null, contentType: String = "application/x-www-form-urlencoded", authenticate: Boolean = false, basicCredentials: String? = null): HttpResponse<String> {
        val builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path")).timeout(Duration.ofSeconds(10))
        if (body != null) builder.header("Content-Type", contentType).POST(HttpRequest.BodyPublishers.ofString(body))
        val credentials = basicCredentials ?: if (authenticate) "configured-web-client:dummy-web-secret" else null
        if (credentials != null) builder.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials.toByteArray()))
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun json(response: HttpResponse<String>): Map<String, Any> = mapper.readValue(response.body(), object : TypeReference<Map<String, Any>>() {})

    private fun form(values: Map<String, String>): String = values.entries.joinToString("&") {
        URLEncoder.encode(it.key, Charsets.UTF_8) + "=" + URLEncoder.encode(it.value, Charsets.UTF_8)
    }
}
