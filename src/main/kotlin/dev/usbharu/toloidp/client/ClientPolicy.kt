package dev.usbharu.toloidp.client

import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.Duration

/** Typed view of the policy stored in a RegisteredClient; it has no separate persistence. */
data class ClientPolicy(
    val clientId: String,
    val clientType: ClientType,
    val allowedGrantTypes: Set<String>,
    val allowedTransitions: Set<String>,
    val allowedAudiences: Set<String>,
    val allowedScopes: Set<String>,
    val tenantAccessTtl: Duration,
    val eventAccessTtl: Duration,
    val tokenIntrospectionAllowed: Boolean = false,
) {
    fun toRegisteredClient(client: RegisteredClient): RegisteredClient {
        require(client.clientId == clientId) { "Client policy id does not match the registered client." }
        return RegisteredClient.from(client)
            .authorizationGrantTypes { grants ->
                grants.clear()
                grants.addAll(allowedGrantTypes.map(::AuthorizationGrantType))
            }
            .scopes { scopes -> scopes.clear(); scopes.addAll(allowedScopes) }
            .clientSettings(
                ClientSettings.withSettings(client.clientSettings.settings)
                    .setting(CLIENT_TYPE, clientType.name)
                    .setting(ALLOWED_AUDIENCES, ArrayList(allowedAudiences))
                    .setting(ALLOWED_TRANSITIONS, ArrayList(allowedTransitions))
                    .setting(TOKEN_INTROSPECTION_ALLOWED, tokenIntrospectionAllowed)
                    .build(),
            )
            .tokenSettings(
                TokenSettings.withSettings(client.tokenSettings.settings)
                    .accessTokenTimeToLive(tenantAccessTtl)
                    .setting(EVENT_ACCESS_TTL_SECONDS, eventAccessTtl.seconds)
                    .build(),
            )
            .build()
    }

    companion object {
        const val CLIENT_TYPE = "tolo-idp.client-type"
        const val ALLOWED_AUDIENCES = "tolo-idp.allowed-audiences"
        const val ALLOWED_TRANSITIONS = "tolo-idp.allowed-token-exchange-transitions"
        const val EVENT_ACCESS_TTL_SECONDS = "tolo-idp.event-access-ttl-seconds"
        const val TOKEN_INTROSPECTION_ALLOWED = "tolo-idp.token-introspection-allowed"

        /** Missing or malformed settings fail closed at the authorization boundary. */
        fun from(client: RegisteredClient): ClientPolicy? {
            val settings = client.clientSettings.settings
            val type = ClientType.entries.firstOrNull { it.name == settings[CLIENT_TYPE] } ?: return null
            val audiences = stringSet(settings[ALLOWED_AUDIENCES]) ?: return null
            val transitions = stringSet(settings[ALLOWED_TRANSITIONS]) ?: return null
            val tokenIntrospectionAllowed = settings[TOKEN_INTROSPECTION_ALLOWED] as? Boolean ?: return null
            val ttl = client.tokenSettings.settings[EVENT_ACCESS_TTL_SECONDS]
            val seconds = when (ttl) {
                is Long -> ttl
                is Int -> ttl.toLong()
                else -> return null
            }
            if (seconds <= 0) return null
            return ClientPolicy(
                clientId = client.clientId,
                clientType = type,
                allowedGrantTypes = client.authorizationGrantTypes.map { it.value }.toSet(),
                allowedTransitions = transitions,
                allowedAudiences = audiences,
                allowedScopes = client.scopes,
                tenantAccessTtl = client.tokenSettings.accessTokenTimeToLive,
                eventAccessTtl = Duration.ofSeconds(seconds),
                tokenIntrospectionAllowed = tokenIntrospectionAllowed,
            )
        }

        private fun stringSet(value: Any?): Set<String>? {
            if (value !is Collection<*> || value.any { it !is String || it.isBlank() }) return null
            return value.filterIsInstance<String>().toSet()
        }
    }
}

enum class ClientType {
    CONFIDENTIAL,
    PUBLIC,
}
