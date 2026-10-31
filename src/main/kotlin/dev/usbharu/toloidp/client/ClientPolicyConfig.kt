package dev.usbharu.toloidp.client

import dev.usbharu.toloidp.scope.IdpScopes
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import java.time.Duration

/** Binds to tolo-idp.clients.<registration-key>; protocol fields remain in Spring Boot's configuration. */
data class ClientPolicyConfig(
    val allowedAudiences: Set<String> = emptySet(),
    val allowedTokenExchangeTransitions: Set<String> = emptySet(),
    val tenantAccessTtl: Duration = Duration.ofMinutes(15),
    val eventAccessTtl: Duration = Duration.ofMinutes(10),
    val tokenIntrospectionAllowed: Boolean = false,
) {
    fun toPolicy(clientId: String, client: OAuth2AuthorizationServerProperties.Client): ClientPolicy {
        val registration = client.registration
        val isPublic = ClientAuthenticationMethod.NONE.value in registration.clientAuthenticationMethods
        require(!isPublic || registration.clientAuthenticationMethods.size == 1) {
            "Client '$clientId' must not mix public and confidential authentication methods."
        }
        require(allowedAudiences.isNotEmpty() && allowedAudiences.none { it.isBlank() }) {
            "Client '$clientId' requires non-blank allowed audiences."
        }
        require(tenantAccessTtl.seconds > 0 && tenantAccessTtl.nano == 0 &&
            eventAccessTtl.seconds > 0 && eventAccessTtl.nano == 0
        ) { "Client '$clientId' token TTLs must be positive whole seconds." }
        require(IdpScopes.SUPPORTED.containsAll(registration.scopes)) {
            "Client '$clientId' contains unsupported scopes."
        }
        val exchange = AuthorizationGrantType.TOKEN_EXCHANGE.value in registration.authorizationGrantTypes
        require(!isPublic || !exchange) { "Public client '$clientId' must not enable token exchange." }
        require(!isPublic || !tokenIntrospectionAllowed) { "Public client '$clientId' must not enable token introspection." }
        require(allowedTokenExchangeTransitions.all { it == "tenant_access:event_access" }) {
            "Client '$clientId' contains an unsupported token exchange transition."
        }
        require(allowedTokenExchangeTransitions.isEmpty() || exchange) {
            "Client '$clientId' exchange transitions require the token exchange grant."
        }
        require(client.token.accessTokenFormat == "self-contained") {
            "Client '$clientId' must use JWT access tokens."
        }
        return ClientPolicy(
            clientId = clientId,
            clientType = if (isPublic) ClientType.PUBLIC else ClientType.CONFIDENTIAL,
            allowedGrantTypes = registration.authorizationGrantTypes,
            allowedTransitions = allowedTokenExchangeTransitions,
            allowedAudiences = allowedAudiences,
            allowedScopes = registration.scopes,
            tenantAccessTtl = tenantAccessTtl,
            eventAccessTtl = eventAccessTtl,
            tokenIntrospectionAllowed = tokenIntrospectionAllowed,
        )
    }
}
