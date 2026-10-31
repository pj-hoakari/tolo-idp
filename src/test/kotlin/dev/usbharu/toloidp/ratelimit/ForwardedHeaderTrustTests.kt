package dev.usbharu.toloidp.ratelimit

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.context.annotation.Import
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.assertEquals

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "server.address=127.0.0.1",
        "tolo-idp.rate-limit.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:forwarded-internal-proxy;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
    ],
)
@Import(RateLimitFilterTests.Config::class)
class ForwardedHeadersFromInternalProxyTests(
    @LocalServerPort private val port: Int,
    @Autowired private val rateLimitService: RecordingRateLimitService,
) {
    @Test
    fun clientAddressForwardedByAnInternalProxyIsUsed() {
        assertEquals("198.51.100.7", clientAddressSeen(port, rateLimitService))
    }
}

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "server.address=127.0.0.1",
        "server.tomcat.remoteip.internal-proxies=192.0.2.1/32",
        "tolo-idp.rate-limit.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:forwarded-untrusted-peer;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false",
    ],
)
@Import(RateLimitFilterTests.Config::class)
class ForwardedHeadersFromUntrustedPeerTests(
    @LocalServerPort private val port: Int,
    @Autowired private val rateLimitService: RecordingRateLimitService,
) {
    @Test
    fun clientAddressForwardedByAnUntrustedPeerIsIgnored() {
        assertEquals("127.0.0.1", clientAddressSeen(port, rateLimitService))
    }
}

private fun clientAddressSeen(port: Int, rateLimitService: RecordingRateLimitService): String? {
    rateLimitService.reset()
    HttpClient.newHttpClient().use { http ->
        val response = http.send(
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:$port/actuator/health"))
                .header("X-Forwarded-For", "198.51.100.7").build(),
            HttpResponse.BodyHandlers.discarding(),
        )
        assertEquals(200, response.statusCode())
    }
    return rateLimitService.lastIdentity.get()?.ip
}
