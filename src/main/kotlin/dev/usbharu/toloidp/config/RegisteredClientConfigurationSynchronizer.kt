package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.logging.structuredDebug
import dev.usbharu.toloidp.logging.structuredInfo
import dev.usbharu.toloidp.logging.structuredTrace
import dev.usbharu.toloidp.logging.structuredWarn
import org.slf4j.LoggerFactory
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm
import org.springframework.security.oauth2.jose.jws.MacAlgorithm
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.transaction.annotation.Transactional
import java.util.Locale

@Configuration
class RegisteredClientSyncConfig {
    @Bean
    fun registeredClientConfigurationSynchronizer(
        properties: OAuth2AuthorizationServerProperties,
        registeredClientRepository: RegisteredClientRepository,
        passwordEncoder: PasswordEncoder,
        jdbcTemplate: JdbcTemplate,
    ): RegisteredClientConfigurationSynchronizer =
        RegisteredClientConfigurationSynchronizer(
            properties,
            registeredClientRepository,
            passwordEncoder,
            jdbcTemplate,
        )
}

/**
 * 構成ファイルの OAuth2 client を JDBC の RegisteredClient へ同期する。
 *
 * `configuration_managed` が真の行だけを構成の削除対象にする。フラグが偽の行は、将来の実行時登録として残す。
 */
open class RegisteredClientConfigurationSynchronizer(
    private val properties: OAuth2AuthorizationServerProperties,
    private val registeredClientRepository: RegisteredClientRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jdbcTemplate: JdbcTemplate,
) : ApplicationRunner {
    @Transactional
    override fun run(args: ApplicationArguments) {
        synchronize(properties.client)
    }

    @Transactional
    open fun synchronize(clients: Map<String, OAuth2AuthorizationServerProperties.Client>) {
        log.structuredTrace(
            "Registered client configuration sync started",
            "event" to "registered_client_configuration_sync_started",
            "configured_client_count" to clients.size,
        )
        val desired = clients.map { (registrationId, client) ->
            DesiredClient(
                registrationId = registrationId,
                client = client,
                clientId = requireClientId(client),
            )
        }
        rejectDuplicateClientIds(desired)
        rejectEmptyClientSettings(desired)
        val existingByClientId = desired.associate { it.clientId to registeredClientRepository.findByClientId(it.clientId) }
        rejectRegistrationIdCollisions(desired, existingByClientId)

        var created = 0
        var updated = 0
        desired.forEach { item ->
            val existing = existingByClientId[item.clientId]
            registeredClientRepository.save(toRegisteredClient(item, existing))
            markConfigurationManaged(item.clientId)
            if (existing == null) {
                created += 1
            } else {
                updated += 1
            }
            log.structuredDebug(
                "Registered client configuration applied",
                "event" to "registered_client_configuration_applied",
                "client_id" to item.clientId,
                "action" to if (existing == null) "created" else "updated",
            )
        }

        val configuredClientIds = desired.map { it.clientId }.toSet()
        val deletedClientIds = managedClientIds().filter { it !in configuredClientIds }
        deletedClientIds.forEach { clientId ->
            // Authorization と consent は RegisteredClient の内部 ID を参照する。
            // 親行の削除前に整理し、照会時の参照切れや再登録時の同意の引き継ぎを防ぐ。
            val managedClientIdQuery =
                "SELECT id FROM oauth2_registered_client WHERE client_id = ? AND configuration_managed = true"
            jdbcTemplate.update(
                "DELETE FROM oauth2_authorization WHERE registered_client_id IN ($managedClientIdQuery)",
                clientId,
            )
            jdbcTemplate.update(
                "DELETE FROM oauth2_authorization_consent WHERE registered_client_id IN ($managedClientIdQuery)",
                clientId,
            )
            jdbcTemplate.update(
                "DELETE FROM oauth2_registered_client WHERE client_id = ? AND configuration_managed = true",
                clientId,
            )
            log.structuredInfo(
                "Configured registered client removed",
                "event" to "registered_client_configuration_removed",
                "client_id" to clientId,
            )
        }
        log.structuredInfo(
            "Registered client configuration synced",
            "event" to "registered_client_configuration_synced",
            "created_count" to created,
            "updated_count" to updated,
            "deleted_count" to deletedClientIds.size,
        )
    }

    private fun requireClientId(client: OAuth2AuthorizationServerProperties.Client): String {
        val clientId = client.registration.clientId
        if (clientId.isNullOrEmpty()) {
            throw IllegalStateException("Client id must not be empty.")
        }
        return clientId
    }

    private fun rejectDuplicateClientIds(desired: List<DesiredClient>) {
        val duplicates = desired.groupingBy { it.clientId }.eachCount().filterValues { it > 1 }.keys.sorted()
        if (duplicates.isEmpty()) {
            return
        }
        log.structuredWarn(
            "Registered client configuration rejected",
            "event" to "registered_client_configuration_rejected",
            "failure_reason" to "duplicate_client_id",
            "client_id" to duplicates.joinToString(","),
        )
        throw IllegalStateException("Duplicate client id in configuration: ${duplicates.joinToString(",")}")
    }

    private fun rejectEmptyClientSettings(desired: List<DesiredClient>) {
        desired.forEach { item ->
            val registration = item.client.registration
            if (registration.clientAuthenticationMethods.isEmpty()) {
                throw IllegalStateException("Client authentication methods must not be empty.")
            }
            if (registration.authorizationGrantTypes.isEmpty()) {
                throw IllegalStateException("Authorization grant types must not be empty.")
            }
        }
    }

    private fun rejectRegistrationIdCollisions(
        desired: List<DesiredClient>,
        existingByClientId: Map<String, RegisteredClient?>,
    ) {
        desired.forEach { item ->
            if (existingByClientId[item.clientId] != null) {
                return@forEach
            }
            val existingById = registeredClientRepository.findById(item.registrationId) ?: return@forEach
            if (existingById.clientId == item.clientId) {
                return@forEach
            }
            log.structuredWarn(
                "Registered client configuration rejected",
                "event" to "registered_client_configuration_rejected",
                "failure_reason" to "registration_id_collision",
                "client_id" to item.clientId,
                "existing_client_id" to existingById.clientId,
            )
            throw IllegalStateException(
                "Registered client id '${item.registrationId}' is already used by client '${existingById.clientId}'.",
            )
        }
    }

    private fun toRegisteredClient(item: DesiredClient, existing: RegisteredClient?): RegisteredClient {
        val registration = item.client.registration
        val builder = RegisteredClient.withId(existing?.id ?: item.registrationId)
        existing?.clientIdIssuedAt?.let(builder::clientIdIssuedAt)
        builder.clientId(item.clientId)
        resolveSecret(registration.clientSecret, existing?.clientSecret)?.let(builder::clientSecret)
        existing?.clientSecretExpiresAt?.let(builder::clientSecretExpiresAt)
        registration.clientName?.let(builder::clientName)
        registration.clientAuthenticationMethods.forEach {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod(it))
        }
        registration.authorizationGrantTypes.forEach {
            builder.authorizationGrantType(AuthorizationGrantType(it))
        }
        registration.redirectUris.forEach(builder::redirectUri)
        registration.postLogoutRedirectUris.forEach(builder::postLogoutRedirectUri)
        registration.scopes.forEach(builder::scope)
        builder.clientSettings(clientSettings(item.client))
        builder.tokenSettings(tokenSettings(item.client))
        return builder.build()
    }

    private fun resolveSecret(configured: String?, existing: String?): String? {
        if (configured.isNullOrEmpty()) {
            return null
        }
        if (configured.startsWith("{")) {
            return configured
        }
        if (existing != null && secretMatches(configured, existing)) {
            return existing
        }
        return passwordEncoder.encode(configured)
    }

    private fun secretMatches(rawPassword: String, encodedPassword: String): Boolean =
        try {
            passwordEncoder.matches(rawPassword, encodedPassword)
        } catch (_: IllegalArgumentException) {
            false
        }

    private fun clientSettings(client: OAuth2AuthorizationServerProperties.Client): ClientSettings {
        val builder = ClientSettings.builder()
            .requireProofKey(client.isRequireProofKey)
            .requireAuthorizationConsent(client.isRequireAuthorizationConsent)
        client.jwkSetUri?.let(builder::jwkSetUrl)
        client.tokenEndpointAuthenticationSigningAlgorithm?.let {
            builder.tokenEndpointAuthenticationSigningAlgorithm(jwsAlgorithm(it))
        }
        return builder.build()
    }

    private fun tokenSettings(client: OAuth2AuthorizationServerProperties.Client): TokenSettings {
        val token = client.token
        return TokenSettings.builder()
            .authorizationCodeTimeToLive(token.authorizationCodeTimeToLive)
            .accessTokenTimeToLive(token.accessTokenTimeToLive)
            .accessTokenFormat(OAuth2TokenFormat(token.accessTokenFormat))
            .deviceCodeTimeToLive(token.deviceCodeTimeToLive)
            .reuseRefreshTokens(token.isReuseRefreshTokens)
            .refreshTokenTimeToLive(token.refreshTokenTimeToLive)
            .idTokenSignatureAlgorithm(signatureAlgorithm(token.idTokenSignatureAlgorithm))
            .build()
    }

    private fun jwsAlgorithm(signingAlgorithm: String): JwsAlgorithm {
        val name = signingAlgorithm.uppercase(Locale.ROOT)
        return SignatureAlgorithm.from(name)
            ?: MacAlgorithm.from(name)
            ?: throw IllegalStateException("Unknown token endpoint authentication signing algorithm: $signingAlgorithm")
    }

    private fun signatureAlgorithm(signatureAlgorithm: String): SignatureAlgorithm =
        SignatureAlgorithm.from(signatureAlgorithm.uppercase(Locale.ROOT))
            ?: throw IllegalStateException("Unknown ID token signature algorithm: $signatureAlgorithm")

    private fun markConfigurationManaged(clientId: String) {
        val updated = jdbcTemplate.update(
            "UPDATE oauth2_registered_client SET configuration_managed = true WHERE client_id = ?",
            clientId,
        )
        if (updated == 0) {
            throw IllegalStateException("Registered client '$clientId' was not stored.")
        }
    }

    private fun managedClientIds(): List<String> =
        jdbcTemplate.queryForList(
            "SELECT client_id FROM oauth2_registered_client WHERE configuration_managed = true",
            String::class.java,
        )

    private data class DesiredClient(
        val registrationId: String,
        val client: OAuth2AuthorizationServerProperties.Client,
        val clientId: String,
    )

    private companion object {
        val log = LoggerFactory.getLogger(RegisteredClientConfigurationSynchronizer::class.java)
    }
}
