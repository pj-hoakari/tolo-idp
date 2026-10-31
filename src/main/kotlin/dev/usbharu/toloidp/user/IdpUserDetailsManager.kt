package dev.usbharu.toloidp.user

import dev.usbharu.toloidp.relation.RelationLookupException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.ResultSetExtractor
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.transaction.annotation.Transactional
import java.util.UUID
import javax.sql.DataSource

/** id is the surrogate key / OIDC subject; username is the userId in the tenant. */
class IdpUserDetails(
    val id: String,
    val tenantId: String,
    private val delegate: UserDetails,
) : UserDetails by delegate {
    override fun isEnabled(): Boolean = delegate.isEnabled
    override fun isAccountNonExpired(): Boolean = delegate.isAccountNonExpired
    override fun isAccountNonLocked(): Boolean = delegate.isAccountNonLocked
    override fun isCredentialsNonExpired(): Boolean = delegate.isCredentialsNonExpired
}

open class IdpUserDetailsManager(dataSource: DataSource, private val passwordEncoder: PasswordEncoder) : UserDetailsService {
    private val jdbc = JdbcTemplate(dataSource)

    // Framework APIs without tenant context cannot identify a tenant-local login name.
    override fun loadUserByUsername(username: String): IdpUserDetails =
        throw UsernameNotFoundException("Tenant is required")

    open fun loadUserByUsername(tenantId: String, username: String): IdpUserDetails =
        load("u.tenant_id = ? AND u.username = ?", tenantId, username)

    open fun loadUserById(id: String): IdpUserDetails = load("u.id = ?", id)

    /** Resolve a subject only inside its owning tenant before querying Relation Service. */
    open fun requireTenantUser(tenantId: String, subject: String): IdpUserDetails {
        val user = try {
            load("u.tenant_id = ? AND u.id = ?", tenantId, subject)
        } catch (_: UsernameNotFoundException) {
            throw RelationLookupException("user_not_tenant_member")
        }
        if (!user.isEnabled) throw RelationLookupException("user_not_tenant_member")
        return user
    }

    private fun load(condition: String, vararg values: String): IdpUserDetails =
        jdbc.query(
            "SELECT u.id, u.tenant_id, u.username, u.password, u.enabled, a.authority FROM idp_users u " +
                "LEFT JOIN idp_user_authorities a ON a.user_id = u.id WHERE $condition",
            ResultSetExtractor { rs ->
                if (!rs.next()) throw UsernameNotFoundException("User not found")
                val id = rs.getString("id")
                val tenantId = rs.getString("tenant_id")
                val builder = User.withUsername(rs.getString("username"))
                    .password(rs.getString("password")).disabled(!rs.getBoolean("enabled"))
                val authorities = mutableListOf<SimpleGrantedAuthority>()
                do {
                    rs.getString("authority")?.let { authorities.add(SimpleGrantedAuthority(it)) }
                } while (rs.next())
                IdpUserDetails(id, tenantId, builder.authorities(authorities).build())
            },
            *values,
        )!!

    open fun userExists(tenantId: String, username: String): Boolean =
        jdbc.queryForObject("SELECT COUNT(*) FROM idp_users WHERE tenant_id = ? AND username = ?",
            Int::class.java, tenantId, username) == 1

    @Transactional
    open fun createUser(tenantId: String, user: UserDetails, id: String = UUID.randomUUID().toString()) {
        require(Regex("^[A-Za-z0-9_-]{1,64}$").matches(tenantId)) { "Invalid tenantId" }
        require(user.username.isNotBlank() && user.username.length <= 50) { "Invalid username" }
        require(UUID.fromString(id).toString() == id) { "id must be a canonical UUID" }
        jdbc.update("INSERT INTO idp_users (id, tenant_id, username, password, enabled) VALUES (?, ?, ?, ?, ?)",
            id, tenantId, user.username, user.password, user.isEnabled)
        saveAuthorities(id, user)
    }

    @Transactional
    open fun updateUser(tenantId: String, user: UserDetails) {
        val stored = loadUserByUsername(tenantId, user.username)
        jdbc.update("UPDATE idp_users SET password = ?, enabled = ? WHERE id = ?", user.password, user.isEnabled, stored.id)
        jdbc.update("DELETE FROM idp_user_authorities WHERE user_id = ?", stored.id)
        saveAuthorities(stored.id, user)
    }

    private fun saveAuthorities(id: String, user: UserDetails) {
        user.authorities.forEach {
            jdbc.update("INSERT INTO idp_user_authorities (user_id, authority) VALUES (?, ?)", id, it.authority)
        }
    }

    @Transactional
    open fun deleteUser(tenantId: String, username: String) {
        if (!userExists(tenantId, username)) return
        val stored = loadUserByUsername(tenantId, username)
        jdbc.update("DELETE FROM idp_user_authorities WHERE user_id = ?", stored.id)
        jdbc.update("DELETE FROM idp_users WHERE id = ?", stored.id)
    }

    @Transactional
    open fun renameUser(id: String, username: String) {
        require(username.isNotBlank() && username.length <= 50) { "Invalid username" }
        if (jdbc.update("UPDATE idp_users SET username = ? WHERE id = ?", username, id) != 1) {
            throw UsernameNotFoundException("User not found")
        }
    }

    /** newPassword is already encoded by the caller. */
    @Transactional
    open fun changePassword(oldPassword: String, newPassword: String) {
        val authentication = SecurityContextHolder.getContext().authentication
            ?: throw AccessDeniedException("Authentication required")
        if (!authentication.isAuthenticated) throw AccessDeniedException("Authentication required")
        val user = loadUserById(authentication.name)
        if (!user.isEnabled || !passwordEncoder.matches(oldPassword, user.password)) throw BadCredentialsException("Bad credentials")
        jdbc.update("UPDATE idp_users SET password = ? WHERE id = ?", newPassword, user.id)
    }

    companion object {
        const val DEVELOPMENT_USER_ID = "71c68dc1-2c72-45ac-a191-1c47c1551011"
    }
}
