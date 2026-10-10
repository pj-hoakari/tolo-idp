package dev.usbharu.toloidp.ratelimit

import dev.usbharu.toloidp.logging.structuredWarn
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.filter.OncePerRequestFilter
import kotlin.math.ceil

class RateLimitFilter(
    private val identityExtractor: RateLimitIdentityExtractor,
    private val rateLimitService: RateLimitService,
) : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val wrappedRequest = try {
            wrapIfNeeded(request)
        } catch (_: RequestBodyTooLargeException) {
            log.structuredWarn(
                "Login body too large",
                "event" to "login_body_too_large",
                "method" to request.method,
                "path" to request.requestURI,
                "status" to HttpStatus.PAYLOAD_TOO_LARGE.value(),
            )
            writeJsonError(response, HttpStatus.PAYLOAD_TOO_LARGE, "payload_too_large", null)
            return
        }
        val identity = identityExtractor.identity(wrappedRequest)
        val decision = try {
            rateLimitService.consume(identity)
        } catch (ex: RateLimitUnavailableException) {
            log.structuredWarn(
                "Rate limit unavailable",
                ex,
                "event" to "rate_limit_unavailable",
                "method" to request.method,
                "path" to request.requestURI,
                "status" to HttpStatus.SERVICE_UNAVAILABLE.value(),
            )
            writeJsonError(response, HttpStatus.SERVICE_UNAVAILABLE, "rate_limit_unavailable", null)
            return
        }

        if (!decision.allowed) {
            log.structuredWarn(
                "Request rate limited",
                "event" to "rate_limit_rejected",
                "dimension" to decision.rejectedDimension?.name.orEmpty().lowercase(),
                "method" to request.method,
                "path" to request.requestURI,
                "status" to HttpStatus.TOO_MANY_REQUESTS.value(),
            )
            writeJsonError(response, HttpStatus.TOO_MANY_REQUESTS, "rate_limited", decision)
            return
        }

        filterChain.doFilter(wrappedRequest, response)
    }

    private fun wrapIfNeeded(request: HttpServletRequest): HttpServletRequest {
        if (request is CachedBodyHttpServletRequest) {
            return request
        }
        if (request.method == "POST" &&
            request.requestURI == "/api/login" &&
            request.contentType.orEmpty().startsWith(MediaType.APPLICATION_JSON_VALUE)
        ) {
            return CachedBodyHttpServletRequest(request)
        }
        return request
    }

    private fun writeJsonError(
        response: HttpServletResponse,
        status: HttpStatus,
        error: String,
        decision: RateLimitDecision?,
    ) {
        response.status = status.value()
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        decision?.retryAfter
            ?.takeIf { !it.isNegative && !it.isZero }
            ?.let { response.setHeader(HttpHeaders.RETRY_AFTER, ceil(it.toMillis() / 1000.0).toLong().toString()) }
        response.writer.write("""{"error":"$error"}""")
    }

    companion object {
        private val log = LoggerFactory.getLogger(RateLimitFilter::class.java)
    }
}

