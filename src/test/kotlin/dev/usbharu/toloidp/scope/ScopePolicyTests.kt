package dev.usbharu.toloidp.scope

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource

class ScopePolicyTests {
    private val policy = ScopePolicy()

    @ParameterizedTest
    @EnumSource(value = RelationRole::class, names = ["OWNER", "ADMIN"])
    fun managersAllowAllBusinessScopes(role: RelationRole) {
        assertEquals(
            setOf("tenant.read", "tenant.write", "tenant.claim", "events.read", "events.manage", "events.operate", "events.report"),
            policy.allowedScopes(role),
        )
    }

    @Test
    fun staffAllowsReadOperationReportAndClaimScopes() {
        assertEquals(
            setOf("tenant.read", "tenant.claim", "events.read", "events.operate", "events.report"),
            policy.allowedScopes(RelationRole.STAFF),
        )
    }

    @ParameterizedTest
    @ValueSource(strings = ["tenant.write", "events.manage"])
    fun staffDoesNotAllowManagementScopes(scope: String) {
        assertFailsWith<ScopeNotAllowedException> {
            policy.requireTenantAccessScopes(setOf(scope), RelationRole.STAFF, "scope_not_allowed_for_role")
        }
    }

    @ParameterizedTest
    @EnumSource(RelationRole::class)
    fun claimIsAllowedAloneOrWithOpenIdForEveryRole(role: RelationRole) {
        policy.requireTenantAccessScopes(setOf("tenant.claim"), role, "scope_not_allowed_for_role")
        policy.requireTenantAccessScopes(setOf("openid", "tenant.claim"), role, "scope_not_allowed_for_role")
    }

    @ParameterizedTest
    @ValueSource(strings = ["tenant.read", "tenant.write", "events.read", "events.manage", "events.operate", "events.report"])
    fun claimCannotBeMixedWithBusinessScopes(scope: String) {
        assertFailsWith<ScopeNotAllowedException> {
            policy.requireTenantAccessScopes(setOf("openid", "tenant.claim", scope), RelationRole.OWNER, "scope_not_allowed_for_role")
        }
    }

    @ParameterizedTest
    @EnumSource(RelationRole::class)
    fun legacyWriteScopeIsRejectedForEveryRole(role: RelationRole) {
        assertFailsWith<ScopeNotAllowedException> {
            policy.requireTenantAccessScopes(setOf("events.write"), role, "scope_not_allowed_for_role")
        }
    }

    @Test
    fun eventAccessDoesNotAllowClaim() {
        val exception = assertFailsWith<ScopeNotAllowedException> {
            policy.requireEventAccessScopes(setOf("tenant.claim"))
        }
        assertEquals("scope_not_allowed_for_token_use", exception.reason)
    }

    @Test
    fun identityScopeIsNotSubjectToRoleCheck() {
        policy.requireTenantAccessScopes(setOf("openid", "tenant.read"), RelationRole.STAFF, "scope_not_allowed_for_role")
        policy.requireTenantAccessScopes(setOf("openid"), RelationRole.STAFF, "scope_not_allowed_for_role")
    }

    @Test
    fun identityScopeDoesNotBypassRoleCheckForOtherScopes() {
        val exception = assertFailsWith<ScopeNotAllowedException> {
            policy.requireTenantAccessScopes(setOf("openid", "tenant.write"), RelationRole.STAFF, "scope_not_allowed_for_role")
        }
        assertEquals("scope_not_allowed_for_role", exception.reason)
    }

    @Test
    fun identityScopeIsNotGrantedByRoleHierarchy() {
        assertFalse(policy.allowedScopes(RelationRole.OWNER).contains("openid"))
        assertFailsWith<ScopeNotAllowedException> {
            policy.requireAllowed(setOf("openid"), policy.allowedScopes(RelationRole.OWNER), "scope_not_allowed_for_role")
        }
    }

    @Test
    fun usesInjectedRoleHierarchyForScopeResolution() {
        val customPolicy = ScopePolicy(
            RoleHierarchyImpl.fromHierarchy(
                """
                ROLE_STAFF > SCOPE_events.read
                """.trimIndent(),
            ),
        )

        assertEquals(setOf("events.read"), customPolicy.allowedScopes(RelationRole.STAFF))
    }

    @Test
    fun unknownExternalRoleFails() {
        assertFailsWith<UnknownRelationRoleException> {
            RelationRole.fromExternal("admin")
        }
    }
}
