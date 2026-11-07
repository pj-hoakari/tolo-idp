package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.devicegrant.DeviceGrantRepository
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator

/**
 * Caps refresh token expiry at the device grant's absolute 7-day approval limit.
 *
 * The standard generator owns the sliding 24-hour TTL. Device grants have an additional
 * absolute expiry that must apply to every rotated token as well.
 */
class CappedRefreshTokenGenerator(
    private val delegate: OAuth2TokenGenerator<OAuth2Token>,
    private val deviceGrants: DeviceGrantRepository,
) : OAuth2TokenGenerator<OAuth2Token> {
    override fun generate(context: OAuth2TokenContext): OAuth2Token? {
        val generated = delegate.generate(context) ?: return null
        val grant = context.authorization?.id?.let(deviceGrants::findById) ?: return generated
        val expiresAt = generated.expiresAt ?: return generated
        if (!expiresAt.isAfter(grant.absoluteExpiresAt)) {
            return generated
        }
        return OAuth2RefreshToken(generated.tokenValue, generated.issuedAt, grant.absoluteExpiresAt)
    }
}
