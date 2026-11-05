package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.MediaType
import org.springframework.web.util.UrlPathHelper

private val credentialPaths = setOf("/api/login", "/api/signup")
private val urlPathHelper = UrlPathHelper.defaultInstance

/** Match the same decoded path used by Spring MVC, not the raw encoded request URI. */
fun isCredentialPath(request: HttpServletRequest): Boolean =
    urlPathHelper.getPathWithinApplication(request) in credentialPaths

/** Spring's Jackson converter accepts application/json and vendor +json media types, case-insensitively. */
fun isJsonCredential(contentType: String?): Boolean {
    val mediaType = contentType
        ?.let { runCatching { MediaType.parseMediaType(it) }.getOrNull() }
        ?: return false
    return mediaType.type == "application" &&
        (mediaType.subtype == "json" || mediaType.subtype.endsWith("+json"))
}
