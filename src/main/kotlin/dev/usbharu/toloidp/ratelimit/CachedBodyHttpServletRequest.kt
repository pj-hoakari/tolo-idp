package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader

class CachedBodyHttpServletRequest(
    request: HttpServletRequest,
    maxBytes: Int = MAX_LOGIN_JSON_BYTES,
) : HttpServletRequestWrapper(request) {
    private val body: ByteArray = readAtMost(request, maxBytes)

    fun cachedBody(): ByteArray = body

    override fun getInputStream(): ServletInputStream =
        CachedBodyServletInputStream(body)

    override fun getReader(): BufferedReader =
        BufferedReader(InputStreamReader(inputStream, characterEncoding ?: Charsets.UTF_8.name()))

    companion object {
        /** Login JSON carries only username, password, and tenantId. */
        const val MAX_LOGIN_JSON_BYTES: Int = 8 * 1024
    }
}

class RequestBodyTooLargeException : RuntimeException()

private fun readAtMost(request: HttpServletRequest, maxBytes: Int): ByteArray {
    val declaredLength = request.contentLengthLong
    if (declaredLength > maxBytes) {
        throw RequestBodyTooLargeException()
    }

    val input = request.inputStream
    val buffer = ByteArrayOutputStream(initialCapacity(declaredLength, maxBytes))
    val chunk = ByteArray(minOf(1024, maxBytes.coerceAtLeast(1)))
    var total = 0
    while (total < maxBytes) {
        val read = input.read(chunk, 0, minOf(chunk.size, maxBytes - total))
        if (read < 0) {
            return buffer.toByteArray()
        }
        buffer.write(chunk, 0, read)
        total += read
    }
    if (input.read() >= 0) {
        throw RequestBodyTooLargeException()
    }
    return buffer.toByteArray()
}

private fun initialCapacity(declaredLength: Long, maxBytes: Int): Int =
    when {
        declaredLength > 0 -> declaredLength.toInt()
        else -> minOf(256, maxBytes)
    }

private class CachedBodyServletInputStream(
    body: ByteArray,
) : ServletInputStream() {
    private val delegate = ByteArrayInputStream(body)

    override fun read(): Int = delegate.read()

    override fun isFinished(): Boolean = delegate.available() == 0

    override fun isReady(): Boolean = true

    override fun setReadListener(readListener: ReadListener?) {
        // Synchronous servlet processing only.
    }
}
