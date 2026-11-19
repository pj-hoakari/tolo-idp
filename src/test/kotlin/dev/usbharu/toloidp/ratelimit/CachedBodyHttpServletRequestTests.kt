package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpServletRequest
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Tag("unit")
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

        assertEquals(CachedBodyHttpServletRequest.MAX_LOGIN_JSON_BYTES + 1, body.bytesRead)
    }

    @Test
    fun acceptsExactlyTheMaximumBody() {
        val body = ByteArray(CachedBodyHttpServletRequest.MAX_LOGIN_JSON_BYTES) { 'a'.code.toByte() }
        val request = MockHttpServletRequest("POST", "/api/login").apply {
            contentType = MediaType.APPLICATION_JSON_VALUE
            setContent(body)
        }

        val cached = CachedBodyHttpServletRequest(request)

        assertContentEquals(body, cached.cachedBody())
    }

    @Test
    fun rejectsOneByteOverTheMaximumForChunkedBodies() {
        val body = CountingServletInputStream(CachedBodyHttpServletRequest.MAX_LOGIN_JSON_BYTES + 1)
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

        assertEquals(CachedBodyHttpServletRequest.MAX_LOGIN_JSON_BYTES + 1, body.bytesRead)
    }

    @Test
    fun exposesTheCachedBodyThroughInputStreamAndReader() {
        val body = """{"username":"user"}"""
        val request = MockHttpServletRequest("POST", "/api/login").apply {
            contentType = MediaType.APPLICATION_JSON_VALUE
            characterEncoding = "UTF-8"
            setContent(body.toByteArray())
        }
        val cached = CachedBodyHttpServletRequest(request)

        val stream = cached.inputStream
        assertTrue(stream.isReady)
        assertFalse(stream.isFinished)
        assertEquals(body, stream.readAllBytes().toString(Charsets.UTF_8))
        assertTrue(stream.isFinished)

        assertEquals(body, cached.reader.readText())
    }

    @Test
    fun readerDefaultsToUtf8WhenCharacterEncodingIsNotSet() {
        val body = """{"username":"日本語"}"""
        val request = MockHttpServletRequest("POST", "/api/login").apply {
            contentType = MediaType.APPLICATION_JSON_VALUE
            characterEncoding = null
            setContent(body.toByteArray(Charsets.UTF_8))
        }

        val cached = CachedBodyHttpServletRequest(request)

        assertEquals(body, cached.reader.readText())
    }
}

private const val OVERSIZED_LOGIN_BODY_BYTES = 2 * 1024 * 1024 + 1024

class CountingServletInputStream(
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
