package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.devicegrant.DeviceGrant
import dev.usbharu.toloidp.devicegrant.DeviceGrantRefreshOutcome
import dev.usbharu.toloidp.devicegrant.DeviceGrantRefreshStateException
import dev.usbharu.toloidp.devicegrant.DeviceGrantService
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken

/**
 * Refresh token provider with device-grant revocation, reuse detection and rotation
 * bookkeeping for the ESP camera client. Other clients use the standard SAS provider.
 *
 * This provider is created manually in [dev.usbharu.toloidp.config.SecurityConfig], so it must
 * not rely on its own @Transactional annotation. All state changes go through
 * [DeviceGrantService], which is a Spring-managed transactional bean.
 */
open class SpecRefreshTokenAuthenticationProvider(
    private val delegate: OAuth2RefreshTokenAuthenticationProvider,
    private val deviceGrantService: DeviceGrantService,
    private val cameraClientId: String,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val refreshAuthentication = authentication as OAuth2RefreshTokenAuthenticationToken
        val client = (refreshAuthentication.principal as? OAuth2ClientAuthenticationToken)?.registeredClient
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_client"))
        deviceGrantService.requireCurrentRefreshScopes(
            refreshAuthentication.refreshToken, client, refreshAuthentication.scopes.orEmpty(),
        )
        if (client.clientId != cameraClientId) {
            return delegate.authenticate(authentication)
                ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        }

        val grantForFailure = runCatching {
            deviceGrantService.findGrantByRefreshToken(refreshAuthentication.refreshToken)
        }.getOrNull()
        val outcome = try {
            deviceGrantService.refresh(refreshAuthentication.refreshToken, client.clientId) {
                delegate.authenticate(authentication) as? OAuth2AccessTokenAuthenticationToken
                    ?: throw OAuth2AuthenticationException(OAuth2Error("server_error"))
            }
        } catch (ex: DeviceGrantRefreshStateException) {
            // The refresh transaction rolled back. Fail closed in a new transaction so the
            // presented refresh token cannot be used again.
            revokeAfterFailedRefresh(ex.grant)
            when (val cause = ex.cause) {
                is OAuth2AuthenticationException -> throw cause
                else -> throw OAuth2AuthenticationException(OAuth2Error("server_error"))
            }
        } catch (ex: OAuth2AuthenticationException) {
            throw ex
        } catch (ex: RuntimeException) {
            // Commit or transaction-manager failures happen after the service method returns.
            // They also roll back the consumption, so revoke in a new transaction.
            if (grantForFailure != null) {
                revokeAfterFailedRefresh(grantForFailure)
            }
            throw OAuth2AuthenticationException(OAuth2Error("server_error"))
        }

        return when (outcome) {
            is DeviceGrantRefreshOutcome.Issued -> outcome.authentication
            DeviceGrantRefreshOutcome.Rejected ->
                throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2RefreshTokenAuthenticationToken::class.java.isAssignableFrom(authentication)

    private fun revokeAfterFailedRefresh(grant: DeviceGrant) {
        runCatching { deviceGrantService.revokeAfterFailedRefresh(grant) }
            .onFailure { revocationFailure ->
                log.warn(
                    "Failed to revoke a device grant after a refresh state persistence failure",
                    revocationFailure,
                )
            }
    }

    private companion object {
        val log = LoggerFactory.getLogger(SpecRefreshTokenAuthenticationProvider::class.java)
    }
}
