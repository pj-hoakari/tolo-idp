package dev.usbharu.toloidp.security

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.springframework.test.context.DynamicPropertyRegistry
import java.net.InetSocketAddress
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

object RegistrationGrantStub {
    data class Verification(val tenantId: String, val body: String)

    private val verifications = CopyOnWriteArrayList<Verification>()
    private val verifyPath = Regex("/tenants/([^/]+)/registration-grants/verify")

    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
        createContext("/") { exchange -> answer(exchange) }
        val ready = CountDownLatch(1)
        Thread(ServerStarter(this, ready)).apply {
            isDaemon = true
            start()
        }
        check(ready.await(30, TimeUnit.SECONDS)) { "Registration grant stub did not start" }
    }

    fun register(registry: DynamicPropertyRegistry) {
        registry.add("tolo-idp.relation.base-url") { "http://127.0.0.1:${server.address.port}" }
    }

    fun validToken(): String = "valid-${UUID.randomUUID()}"

    fun invalidToken(): String = "invalid-${UUID.randomUUID()}"

    fun failingToken(status: Int): String = "status-$status-${UUID.randomUUID()}"

    fun answerlessToken(): String = "answerless-${UUID.randomUUID()}"

    fun verificationsOf(token: String): List<Verification> = verifications.filter { "\"$token\"" in it.body }

    private fun answer(exchange: HttpExchange) {
        val match = verifyPath.matchEntire(exchange.requestURI.rawPath)
        if (exchange.requestMethod != "POST" || match == null) {
            exchange.send(404, """{"error":"not found"}""")
            return
        }
        val body = exchange.requestBody.readAllBytes().decodeToString()
        verifications += Verification(match.groupValues[1], body)
        val failingStatus = Regex("\"status-(\\d{3})-").find(body)?.groupValues?.get(1)?.toInt()
        when {
            failingStatus != null -> exchange.send(failingStatus, """{"error":"stubbed failure"}""")
            "\"valid-" in body -> exchange.send(200, """{"valid":true}""")
            "\"answerless-" in body -> exchange.send(200, "{}")
            else -> exchange.send(200, """{"valid":false}""")
        }
    }

    private fun HttpExchange.send(status: Int, body: String) {
        val bytes = body.toByteArray()
        responseHeaders.add("Content-Type", "application/json")
        sendResponseHeaders(status, bytes.size.toLong())
        responseBody.use { it.write(bytes) }
    }

    private class ServerStarter(
        private val server: HttpServer,
        private val ready: CountDownLatch,
    ) : Runnable {
        override fun run() {
            server.start()
            ready.countDown()
        }
    }
}
