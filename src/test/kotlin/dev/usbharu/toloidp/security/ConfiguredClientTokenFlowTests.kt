package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.Test
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

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "server.address=127.0.0.1",
        "spring.datasource.url=jdbc:h2:mem:configured-client-flow;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.client-id=configured-web-client",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.client-secret=dummy-web-secret",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.client-authentication-methods=client_secret_basic",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.authorization-grant-types=authorization_code,urn:ietf:params:oauth:grant-type:token-exchange",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.redirect-uris=https://example.invalid/callback",
        "spring.security.oauth2.authorizationserver.client.web-app.registration.scopes=openid,tenant.read,events.read",
        "spring.security.oauth2.authorizationserver.client.web-app.require-proof-key=true",
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
            val login = send(http, "/api/login", body = """{"username":"user-123","password":"password","tenantId":"tenant-a"}""", contentType = "application/json")
            assertEquals(200, login.statusCode())
            try {
                val redirect = "https://example.invalid/callback"
                val query = form(mapOf(
                    "response_type" to "code", "client_id" to "configured-web-client", "redirect_uri" to redirect,
                    "scope" to "openid tenant.read events.read", "audience" to "configured-api",
                    "state" to "fixture-state", "nonce" to "fixture-nonce",
                    "code_challenge" to "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method" to "S256",
                ))
                val authorize = send(http, "/oauth2/authorize?$query")
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

    private fun send(http: HttpClient, path: String, body: String? = null, contentType: String = "application/x-www-form-urlencoded", authenticate: Boolean = false): HttpResponse<String> {
        val builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path")).timeout(Duration.ofSeconds(10))
        if (body != null) builder.header("Content-Type", contentType).POST(HttpRequest.BodyPublishers.ofString(body))
        if (authenticate) builder.header("Authorization", "Basic " + Base64.getEncoder().encodeToString("configured-web-client:dummy-web-secret".toByteArray()))
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun json(response: HttpResponse<String>): Map<String, Any> = mapper.readValue(response.body(), object : TypeReference<Map<String, Any>>() {})

    private fun form(values: Map<String, String>): String = values.entries.joinToString("&") {
        URLEncoder.encode(it.key, Charsets.UTF_8) + "=" + URLEncoder.encode(it.value, Charsets.UTF_8)
    }
}
