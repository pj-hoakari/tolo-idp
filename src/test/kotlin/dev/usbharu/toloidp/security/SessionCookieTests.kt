package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "server.address=127.0.0.1",
        "spring.datasource.url=jdbc:h2:mem:session-cookie;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
    ],
)
class SessionCookieTests(
    @LocalServerPort private val port: Int,
    @Autowired private val memberships: RelationMembershipCacheRepository,
) {
    @Test
    fun loginStateCookieIsHostOnlySecureHttpOnlyAndLax() {
        memberships.save(RelationMembershipCache(
            cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
            membership = TenantMembership("tenant-a", RelationRole.OWNER, emptyList()),
            cachedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(300),
        ))
        HttpClient.newHttpClient().use { http ->
            val query = mapOf(
                "response_type" to "code", "client_id" to "client-123",
                "redirect_uri" to "http://127.0.0.1:8080/login/oauth2/code/client-123",
                "scope" to "openid tenant.read", "resource" to "https://api.example.com/tenants/tenant-a",
                "code_challenge" to "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method" to "S256",
            ).entries.joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, Charsets.UTF_8)}" }
            val authorize = http.send(request("/oauth2/authorize?$query").build(), HttpResponse.BodyHandlers.discarding())
            assertTrue(authorize.headers().allValues("Set-Cookie").isEmpty())
            val challenge = loginChallenge(authorize.headers().firstValue("Location").orElseThrow())
            val login = http.send(
                request("/api/login").header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("""{"username":"user-123","password":"password","challenge":"$challenge"}"""))
                    .build(),
                HttpResponse.BodyHandlers.discarding(),
            )
            assertEquals(200, login.statusCode())
            val cookie = login.headers().allValues("Set-Cookie").single()
            assertTrue(cookie.startsWith("__Host-tolo_idp_session="))
            assertEquals(
                setOf("path=/", "secure", "httponly", "samesite=lax"),
                cookie.split(';').drop(1).map { it.trim().lowercase() }.toSet(),
            )
        }
    }

    private fun request(path: String) = HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port$path"))
}
