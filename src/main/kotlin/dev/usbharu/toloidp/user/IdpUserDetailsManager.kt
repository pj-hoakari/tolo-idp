package dev.usbharu.toloidp.user

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.transaction.annotation.Transactional
import org.springframework.jdbc.core.ResultSetExtractor
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import java.util.UUID
import javax.sql.DataSource

/** username is a login credential; userId is the stable identity used by sessions and tokens. */
class IdpUserDetails(
    val userId: String,
    private val delegate: UserDetails,
) : UserDetails by delegate {
    override fun isEnabled(): Boolean = delegate.isEnabled
    override fun isAccountNonExpired(): Boolean = delegate.isAccountNonExpired
    override fun isAccountNonLocked(): Boolean = delegate.isAccountNonLocked
    override fun isCredentialsNonExpired(): Boolean = delegate.isCredentialsNonExpired
}

open class IdpUserDetailsManager(dataSource: DataSource) : JdbcUserDetailsManager(dataSource) {
    private val jdbc = JdbcTemplate(dataSource)

    init {
        setUsersByUsernameQuery("SELECT username, password, enabled FROM idp_users WHERE username = ?")
        setAuthoritiesByUsernameQuery(
            "SELECT u.username, a.authority FROM idp_user_authorities a " +
                "JOIN idp_users u ON u.id = a.user_id WHERE u.username = ?",
        )
        setUpdateUserSql("UPDATE idp_users SET password = ?, enabled = ? WHERE username = ?")
        setUserExistsSql("SELECT COUNT(*) FROM idp_users WHERE username = ?")
        setCreateAuthoritySql(
            "INSERT INTO idp_user_authorities (user_id, authority) " +
                "VALUES ((SELECT id FROM idp_users WHERE username = ?), ?)",
        )
        setDeleteUserAuthoritiesSql(
            "DELETE FROM idp_user_authorities WHERE user_id = (SELECT id FROM idp_users WHERE username = ?)",
        )
        setDeleteUserSql("DELETE FROM idp_users WHERE username = ?")
    }

    override fun loadUserByUsername(username: String): IdpUserDetails = load("u.username", username)

    open fun loadUserById(userId: String): IdpUserDetails = load("u.id", userId)

    // Read credentials, identity and authorities in one query so a reused username cannot mix identities.
    private fun load(column: String, value: String): IdpUserDetails =
        jdbc.query(
            "SELECT u.id, u.username, u.password, u.enabled, a.authority FROM idp_users u " +
                "LEFT JOIN idp_user_authorities a ON a.user_id = u.id WHERE $column = ?",
            ResultSetExtractor { rs ->
                if (!rs.next()) throw UsernameNotFoundException("User not found")
                val id = rs.getString("id")
                val builder = User.withUsername(rs.getString("username"))
                    .password(rs.getString("password"))
                    .disabled(!rs.getBoolean("enabled"))
                val authorities = mutableListOf<SimpleGrantedAuthority>()
                do {
                    rs.getString("authority")?.let { authorities.add(SimpleGrantedAuthority(it)) }
                } while (rs.next())
                IdpUserDetails(id, builder.authorities(authorities).build())
            },
            value,
        )!!

    @Transactional
    override fun createUser(user: UserDetails) {
        createUser(user, UUID.randomUUID().toString())
    }

    /** Explicit IDs are only used for reproducible development seed data. */
    @Transactional
    open fun createUser(user: UserDetails, userId: String) {
        require(user.username.isNotBlank() && user.username.length <= 50) { "Invalid username" }
        require(UUID.fromString(userId).toString() == userId) { "userId must be a canonical UUID" }
        jdbc.update("INSERT INTO idp_users (id, username, password, enabled) VALUES (?, ?, ?, ?)",
            userId, user.username, user.password, user.isEnabled)
        user.authorities.forEach {
            jdbc.update("INSERT INTO idp_user_authorities (user_id, authority) VALUES (?, ?)", userId, it.authority)
        }
    }

    @Transactional
    override fun updateUser(user: UserDetails) = super.updateUser(user)

    @Transactional
    override fun deleteUser(username: String) = super.deleteUser(username)

    @Transactional
    open fun renameUser(userId: String, username: String) {
        require(username.isNotEmpty() && username.length <= 50) { "Invalid username" }
        if (jdbc.update("UPDATE idp_users SET username = ? WHERE id = ?", username, userId) != 1) {
            throw UsernameNotFoundException("User not found")
        }
    }

    // Like JdbcUserDetailsManager, newPassword is already encoded by the caller.
    @Transactional
    override fun changePassword(oldPassword: String, newPassword: String) {
        val authentication = SecurityContextHolder.getContext().authentication
            ?: throw AccessDeniedException("Authentication required")
        if (!authentication.isAuthenticated) throw AccessDeniedException("Authentication required")
        val user = loadUserById(authentication.name)
        if (!user.isEnabled || !PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(oldPassword, user.password)) {
            throw BadCredentialsException("Bad credentials")
        }
        jdbc.update("UPDATE idp_users SET password = ? WHERE id = ?", newPassword, user.userId)
    }

    companion object {
        const val DEVELOPMENT_USER_ID = "71c68dc1-2c72-45ac-a191-1c47c1551011"
    }
}
