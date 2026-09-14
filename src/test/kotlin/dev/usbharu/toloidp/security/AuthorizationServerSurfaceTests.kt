package dev.usbharu.toloidp.security

import org.hamcrest.Matchers.containsInAnyOrder
import org.hamcrest.Matchers.hasItem
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationServerSurfaceTests(
    @Autowired private val mockMvc: MockMvc,
) {
    @Test
    fun openIdProviderConfigurationOnlyAdvertisesSupportedSurface() {
        mockMvc.perform(get("/.well-known/openid-configuration"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.issuer").value("http://localhost:8080"))
            .andExpect(jsonPath("$.authorization_endpoint").exists())
            .andExpect(jsonPath("$.token_endpoint").exists())
            .andExpect(jsonPath("$.jwks_uri").exists())
            .andExpect(
                jsonPath(
                    "$.grant_types_supported",
                    containsInAnyOrder(
                        AuthorizationGrantType.AUTHORIZATION_CODE.value,
                        AuthorizationGrantType.TOKEN_EXCHANGE.value,
                    ),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.scopes_supported",
                    containsInAnyOrder("openid", "tenant.read", "tenant.write", "events.read", "events.write"),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.token_endpoint_auth_methods_supported",
                    containsInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.introspection_endpoint_auth_methods_supported",
                    containsInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.revocation_endpoint_auth_methods_supported",
                    containsInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value),
                ),
            )
    }

    @Test
    fun authorizationServerMetadataOnlyAdvertisesSupportedSurface() {
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.revocation_endpoint").exists())
            .andExpect(
                jsonPath(
                    "$.revocation_endpoint_auth_methods_supported",
                    containsInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.grant_types_supported",
                    containsInAnyOrder(
                        AuthorizationGrantType.AUTHORIZATION_CODE.value,
                        AuthorizationGrantType.TOKEN_EXCHANGE.value,
                    ),
                ),
            )
            .andExpect(jsonPath("$.grant_types_supported", not(hasItem("client_credentials"))))
            .andExpect(jsonPath("$.grant_types_supported", not(hasItem("refresh_token"))))
            .andExpect(
                jsonPath(
                    "$.scopes_supported",
                    containsInAnyOrder("openid", "tenant.read", "tenant.write", "events.read", "events.write"),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.token_endpoint_auth_methods_supported",
                    containsInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.introspection_endpoint_auth_methods_supported",
                    containsInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value),
                ),
            )
            .andExpect(
                jsonPath(
                    "$.revocation_endpoint_auth_methods_supported",
                    containsInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value),
                ),
            )
            .andExpect(jsonPath("$.introspection_endpoint").exists())
    }

    @Test
    fun tokenRevocationEndpointRequiresTokenParameter() {
        mockMvc.perform(
            post("/oauth2/revoke")
                .with(httpBasic("client-123", "secret"))
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
    }
}
