package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.relation.CachedRelationService
import dev.usbharu.toloidp.relation.RelationCacheController
import dev.usbharu.toloidp.relation.RelationMembershipCacheStore
import dev.usbharu.toloidp.security.SpecTokenExchangeAuthenticationProvider
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar

/** Reflection used only by transaction metadata assertions, outside application contexts. */
class NativeTestRuntimeHints : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        listOf(
            AuditService::class.java,
            CachedRelationService::class.java,
            RelationCacheController::class.java,
            RelationMembershipCacheStore::class.java,
            SpecTokenExchangeAuthenticationProvider::class.java,
            SeedDataRunner::class.java,
            RegisteredClientConfigurationSynchronizer::class.java,
        ).forEach { hints.reflection().registerType(it, MemberCategory.INVOKE_PUBLIC_METHODS) }
    }
}
