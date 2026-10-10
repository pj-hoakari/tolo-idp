package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpServletRequest
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CachedBodyHttpServletRequestTests {
    @Test
    fun declaredLengthOverLimitDoesNotReadTheBody() {
        val request = object : MockHttpServletRequest("POST", "/api/login") {
            override fun getContentLengthLong(): Long = OVERSIZED_LOGIN_BODY_BYTES.toLong()

            override fun getContentLength(): Int = OVERSIZED_LOGIN_BODY_BYTES

            override fun getInputStream(): ServletInputStream = error("body was read")
        }.apply {
            contentType = MediaType.APPLICATION_JSON_VALUE
        }

        assertFailsWith<RequestBodyTooLargeException> {
            CachedBodyHttpServletRequest(request)
        }
    }

    @Test
    fun chunkedBodyStopsBeforeTheFullPayloadIsCached() {
        val body = CountingServletInputStream(OVERSIZED_LOGIN_BODY_BYTES)
        val request = object : MockHttpServletRequest("POST", "/api/login") {
            override fun getContentLengthLong(): Long = -1

            override fun getContentLength(): Int = -1

            override fun getInputStream(): ServletInputStream = body
        }.apply {
            contentType = MediaType.APPLICATION_JSON_VALUE
        }

        assertFailsWith<RequestBodyTooLargeException> {
            CachedBodyHttpServletRequest(request)
        }

        assertNotEquals(OVERSIZED_LOGIN_BODY_BYTES, body.bytesRead)
        assertTrue(body.bytesRead <= CachedBodyHttpServletRequest.MAX_LOGIN_JSON_BYTES + 1)
    }
}

private const val OVERSIZED_LOGIN_BODY_BYTES = 2 * 1024 * 1024 + 1024

private class CountingServletInputStream(
    private val size: Int,
) : ServletInputStream() {
    var bytesRead: Int = 0
        private set

    override fun read(): Int {
        if (bytesRead >= size) {
            return -1
        }
        bytesRead += 1
        return ' '.code
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) {
            return 0
        }
        if (bytesRead >= size) {
            return -1
        }
        val count = minOf(length, size - bytesRead)
        bytesRead += count
        return count
    }

    override fun isFinished(): Boolean = bytesRead >= size

    override fun isReady(): Boolean = true

    override fun setReadListener(readListener: ReadListener?) {
        // Synchronous servlet processing only.
    }
}
