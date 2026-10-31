package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationConverter

/**
 * ログイン時に選択された tenant を OAuth2 `resource` パラメータへ結び付ける
 * authorization request converter。
 *
 * ログイン API が作成した Spring Security session から選択 tenant を読み取り、後続の
 * authorization validation と JWT customization が参照する canonical tenant resource URI として表現する。
 */
class TenantAwareAuthorizationRequestConverter(
    private val resourceParser: ResourceParser,
) : AuthenticationConverter {
    private val delegate = OAuth2AuthorizationCodeRequestAuthenticationConverter()

    /**
     * authorization request を変換し、現在の session に選択 tenant がある場合は tenant resource を注入する。
     */
    override fun convert(request: HttpServletRequest): Authentication? {
        val converted = delegate.convert(request)
        if (converted !is OAuth2AuthorizationCodeRequestAuthenticationToken) {
            return converted
        }

        val additionalParameters = converted.additionalParameters.toMutableMap()
        if ("openid" in converted.scopes.orEmpty()) {
            // OIDC Request URI is unsupported. Keep it on the request-local context so
            // our validator can reject it after client/redirect validation, rather than
            // letting the framework interpret it as a pushed authorization request.
            additionalParameters.remove(OAuth2ParameterNames.REQUEST_URI)
        }
        val tenantId = request.getSession(false)?.getAttribute(SELECTED_TENANT_SESSION_ATTRIBUTE) as? String
        if (tenantId != null) additionalParameters[OAuth2ParameterNames.RESOURCE] = resourceParser.tenantResource(tenantId)
        return TenantAuthorizationRequestToken(converted, additionalParameters, request)
    }
}

/** Request-local context only; it is never stored in an authorization or token. */
class TenantAuthorizationRequestToken(
    original: OAuth2AuthorizationCodeRequestAuthenticationToken,
    parameters: Map<String, Any>,
    val httpRequest: HttpServletRequest,
) : OAuth2AuthorizationCodeRequestAuthenticationToken(
    original.authorizationUri, original.clientId, original.principal as Authentication,
    original.redirectUri, original.state, original.scopes, parameters,
)
