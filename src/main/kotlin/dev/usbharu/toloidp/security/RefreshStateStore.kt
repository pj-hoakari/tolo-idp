package dev.usbharu.toloidp.security

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component

interface RefreshStateStore {
    /** Lock the authorization row and return whether refresh was already revoked. */
    fun lockRefreshRevoked(authorizationId: String): Boolean

    /** Mark refresh as revoked on the already locked authorization row. */
    fun markRefreshRevoked(authorizationId: String)
}

@Component
class JdbcRefreshStateStore(
    private val jdbc: JdbcTemplate,
) : RefreshStateStore {
    override fun lockRefreshRevoked(authorizationId: String): Boolean =
        jdbc.queryForObject(
            "SELECT refresh_revoked FROM oauth2_authorization WHERE id = ? FOR UPDATE",
            Boolean::class.java,
            authorizationId,
        ) == true

    override fun markRefreshRevoked(authorizationId: String) {
        jdbc.update("UPDATE oauth2_authorization SET refresh_revoked = true WHERE id = ?", authorizationId)
    }
}
