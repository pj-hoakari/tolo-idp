package dev.usbharu.toloidp.scope

import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component

enum class RelationRole {
    OWNER,
    ADMIN,
    STAFF;

    companion object {
        fun fromExternal(value: String?): RelationRole {
            return when (value) {
                "owner" -> OWNER
                "staff" -> STAFF
                else -> throw UnknownRelationRoleException()
            }
        }
    }
}

class UnknownRelationRoleException : RuntimeException("relation_role_unknown")

/**
 * relation role から scope を導出し、要求 scope を検証する中心的な policy。
 *
 * 呼び出し側は requested scope を明示的に渡す。tenant_access の認可要求ではロールと client の登録 scope を超える scope を発行対象から外し、それ以外の許可外 scope は拒否する。
 */
@Component
class ScopePolicy(
    private val roleHierarchy: RoleHierarchy = defaultRoleHierarchy(),
) {
    /**
     * relation role から role hierarchy 経由で到達できる OAuth2 scope を返す。
     */
    fun allowedScopes(role: RelationRole): Set<String> {
        val reachableAuthorities = roleHierarchy.getReachableGrantedAuthorities(
            listOf(SimpleGrantedAuthority(role.authority)),
        )

        return reachableAuthorities
            .mapNotNull { it.authority }
            .filter { it.startsWith(SCOPE_AUTHORITY_PREFIX) }
            .mapTo(linkedSetOf()) { it.removePrefix(SCOPE_AUTHORITY_PREFIX) }
    }

    /**
     * requested scope がすべて allowed set に含まれることを要求する。
     */
    fun requireAllowed(requested: Set<String>, allowed: Set<String>, reason: String) {
        if (!allowed.containsAll(requested)) {
            throw ScopeNotAllowedException(reason)
        }
    }

    /** tenant role を検証する。 */
    fun requireTenantAccessScopes(requested: Set<String>, role: RelationRole, reason: String) {
        requireAllowed(requested - IDENTITY_SCOPES, allowedScopes(role), reason)
    }

    fun isRegistrationRequest(requested: Set<String>): Boolean = requested == REGISTRATION_SCOPES

    fun requireRegistrationRequest(clientScopes: Set<String>) {
        if (IdpScopes.TENANT_JOIN !in clientScopes) {
            throw ScopeNotAllowedException("scope_not_allowed_for_client")
        }
    }

    fun requireTenantAccessRequest(requested: Set<String>, clientScopes: Set<String>) {
        requireAllowed(requested, IdpScopes.SUPPORTED, "scope_not_allowed_for_role")
        if (IdpScopes.TENANT_JOIN in requested) {
            throw ScopeNotAllowedException("scope_not_allowed_for_token_use")
        }
        if (IdpScopes.OPENID in requested && IdpScopes.OPENID !in clientScopes) {
            throw ScopeNotAllowedException("scope_not_allowed_for_client")
        }
    }

    fun grantTenantAccessScopes(requested: Set<String>, role: RelationRole, clientScopes: Set<String>): Set<String> {
        requireTenantAccessRequest(requested, clientScopes)
        val allowed = (IDENTITY_SCOPES + allowedScopes(role)) intersect clientScopes
        val granted = requested.filterTo(linkedSetOf()) { it in allowed }
        if (granted.isEmpty() && requested.isNotEmpty()) {
            throw ScopeNotAllowedException("scope_not_allowed_for_role")
        }
        return granted
    }

    /** client / subject の保存済み設定にかかわらず、廃止済み scope と tenant.join を拒否する。 */
    fun requireEventAccessScopes(requested: Set<String>) {
        if (IdpScopes.TENANT_JOIN in requested) {
            throw ScopeNotAllowedException("scope_not_allowed_for_token_use")
        }
        requireAllowed(requested, IdpScopes.SUPPORTED, "scope_not_allowed_for_role")
    }

    /**
     * scope を省略した Token Exchange で発行する event_access の既定 scope。
     *
     * event role の許可 scope、subject token の scope、client の登録 scope の積を返す。
     * event_access に載せない scope（openid / profile / tenant.join / events.stream）は除く。
     */
    fun defaultEventAccessScopes(
        subjectScopes: Set<String>,
        role: RelationRole,
        clientScopes: Set<String>,
    ): Set<String> {
        val allowed = allowedScopes(role) intersect clientScopes intersect EVENT_ACCESS_SCOPE_VOCABULARY
        return subjectScopes.filterTo(linkedSetOf()) { it in allowed }
    }

    companion object {
        const val SCOPE_AUTHORITY_PREFIX = "SCOPE_"

        val IDENTITY_SCOPES: Set<String> = IdpScopes.IDENTITY
        val REGISTRATION_SCOPES: Set<String> = setOf(IdpScopes.TENANT_JOIN)
        private val EVENT_ACCESS_SCOPE_VOCABULARY: Set<String> =
            IdpScopes.SUPPORTED - IdpScopes.IDENTITY - IdpScopes.TENANT_JOIN - IdpScopes.EVENTS_STREAM

        fun defaultRoleHierarchy(): RoleHierarchy =
            RoleHierarchyImpl.fromHierarchy(
                """
                ROLE_OWNER > ROLE_STAFF
                ROLE_ADMIN > ROLE_STAFF
                ROLE_OWNER > SCOPE_${IdpScopes.TENANT_WRITE}
                ROLE_ADMIN > SCOPE_${IdpScopes.TENANT_WRITE}
                ROLE_STAFF > SCOPE_${IdpScopes.TENANT_READ}
                ROLE_STAFF > SCOPE_${IdpScopes.EVENTS_READ}
                ROLE_STAFF > SCOPE_${IdpScopes.EVENTS_MANAGE}
                ROLE_STAFF > SCOPE_${IdpScopes.EVENTS_OPERATE}
                ROLE_STAFF > SCOPE_${IdpScopes.EVENTS_REPORT}
                """.trimIndent(),
            )
    }
}

class ScopeNotAllowedException(
    val reason: String,
) : RuntimeException(reason)

private val RelationRole.authority: String
    get() = "ROLE_$name"
