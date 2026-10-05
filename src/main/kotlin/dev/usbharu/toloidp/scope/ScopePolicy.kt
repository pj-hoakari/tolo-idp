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
 * 呼び出し側は requested scope を明示的に渡す。許可外 scope は暗黙に縮小せず拒否する。
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

    /** 所有権取得用 scope と通常の業務 scope の併用を拒否し、tenant role を検証する。 */
    fun requireTenantAccessScopes(requested: Set<String>, role: RelationRole, reason: String) {
        if (IdpScopes.TENANT_CLAIM in requested &&
            (requested - IDENTITY_SCOPES - IdpScopes.TENANT_CLAIM).isNotEmpty()
        ) {
            throw ScopeNotAllowedException(reason)
        }
        requireAllowed(requested - IDENTITY_SCOPES, allowedScopes(role), reason)
    }

    /** client / subject の保存済み設定にかかわらず、廃止済み scope と tenant.claim を拒否する。 */
    fun requireEventAccessScopes(requested: Set<String>) {
        if (IdpScopes.TENANT_CLAIM in requested) {
            throw ScopeNotAllowedException("scope_not_allowed_for_token_use")
        }
        requireAllowed(requested, IdpScopes.SUPPORTED, "scope_not_allowed_for_role")
    }

    companion object {
        const val SCOPE_AUTHORITY_PREFIX = "SCOPE_"

        val IDENTITY_SCOPES: Set<String> = IdpScopes.IDENTITY

        fun defaultRoleHierarchy(): RoleHierarchy =
            RoleHierarchyImpl.fromHierarchy(
                """
                ROLE_OWNER > ROLE_STAFF
                ROLE_ADMIN > ROLE_STAFF
                ROLE_OWNER > SCOPE_${IdpScopes.TENANT_WRITE}
                ROLE_OWNER > SCOPE_${IdpScopes.EVENTS_MANAGE}
                ROLE_ADMIN > SCOPE_${IdpScopes.TENANT_WRITE}
                ROLE_ADMIN > SCOPE_${IdpScopes.EVENTS_MANAGE}
                ROLE_STAFF > SCOPE_${IdpScopes.TENANT_READ}
                ROLE_STAFF > SCOPE_${IdpScopes.TENANT_CLAIM}
                ROLE_STAFF > SCOPE_${IdpScopes.EVENTS_READ}
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
