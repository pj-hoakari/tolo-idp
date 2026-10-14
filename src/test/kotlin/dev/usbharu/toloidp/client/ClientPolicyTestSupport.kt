package dev.usbharu.toloidp.client

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings

fun RegisteredClientRepository.savePolicy(policy: ClientPolicy): RegisteredClient {
    val client = checkNotNull(findByClientId(policy.clientId))
    return policy.toRegisteredClient(client).also(::save)
}

fun RegisteredClientRepository.clearPolicy(clientId: String) {
    val client = checkNotNull(findByClientId(clientId))
    save(
        RegisteredClient.from(client)
            .clientSettings(ClientSettings.withSettings(client.clientSettings.settings).settings { settings ->
                settings.keys.removeIf { it.startsWith("tolo-idp.") }
            }.build())
            .tokenSettings(TokenSettings.withSettings(client.tokenSettings.settings).settings { settings ->
                settings.remove(ClientPolicy.EVENT_ACCESS_TTL_SECONDS)
            }.build())
            .build(),
    )
}
