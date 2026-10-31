package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicyConfig
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.security.oauth2.core.AuthorizationGrantType

fun RegisteredClientConfigurationSynchronizer.synchronizeTestClients(
    clients: Map<String, OAuth2AuthorizationServerProperties.Client>,
) {
    synchronize(clients, clients.mapValues { (_, client) ->
        ClientPolicyConfig(
            allowedAudiences = setOf("backend-api"),
            allowedTokenExchangeTransitions = if (AuthorizationGrantType.TOKEN_EXCHANGE.value in client.registration.authorizationGrantTypes) {
                setOf("tenant_access:event_access")
            } else {
                emptySet()
            },
            tokenIntrospectionAllowed = client.registration.clientId == "service-gateway",
        )
    })
}
