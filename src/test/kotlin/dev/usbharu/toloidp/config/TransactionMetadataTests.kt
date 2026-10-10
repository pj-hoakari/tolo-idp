package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.relation.CachedRelationService
import dev.usbharu.toloidp.relation.RelationCacheController
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.RelationMembershipCacheStore
import dev.usbharu.toloidp.security.JtiDenylistRepository
import dev.usbharu.toloidp.security.SpecTokenExchangeAuthenticationProvider
import org.junit.jupiter.api.Test
import org.springframework.boot.ApplicationArguments
import org.springframework.security.core.Authentication
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TransactionMetadataTests {
    private val transactionAttributes = AnnotationTransactionAttributeSource()

    @Test
    fun `custom repository reads are marked read only`() {
        assertReadOnly(
            ClientPolicyRepository::class.java,
            "findByClientId",
            String::class.java,
        )
        assertReadOnly(
            JtiDenylistRepository::class.java,
            "existsByJtiAndExpiresAtAfter",
            String::class.java,
            java.time.Instant::class.java,
        )
        assertReadOnly(
            RelationMembershipCacheRepository::class.java,
            "findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter",
            String::class.java,
            String::class.java,
            java.time.Instant::class.java,
        )
        assertReadOnly(
            RelationMembershipCacheStore::class.java,
            "lookup",
            String::class.java,
            String::class.java,
            java.time.Instant::class.java,
        )
    }

    @Test
    fun `write capable boundaries are explicit read write transactions`() {
        assertReadWrite(AuditService::class.java, "record", TokenAuditEvent::class.java)
        assertReadWrite(RelationMembershipCacheStore::class.java, "saveIfUnchanged", Long::class.javaPrimitiveType!!, RelationMembershipCache::class.java)
        assertReadWrite(RelationMembershipCacheStore::class.java, "purgeAll")
        assertReadWrite(RelationMembershipCacheStore::class.java, "purgeOne", String::class.java, String::class.java)
        assertReadWrite(RelationCacheController::class.java, "purgeAll")
        assertReadWrite(RelationCacheController::class.java, "purgeOne", String::class.java, String::class.java)
        assertNull(
            transactionAttributes.getTransactionAttribute(
                CachedRelationService::class.java.getMethod("getMembership", String::class.java, String::class.java),
                CachedRelationService::class.java,
            ),
            "CachedRelationService.getMembership should keep the remote call outside a transaction",
        )
        assertReadWrite(SpecTokenExchangeAuthenticationProvider::class.java, "authenticate", Authentication::class.java)
        assertReadWrite(SeedDataRunner::class.java, "run", ApplicationArguments::class.java)
    }

    private fun assertReadOnly(targetClass: Class<*>, methodName: String, vararg parameterTypes: Class<*>) {
        val attribute = transactionAttribute(targetClass, methodName, *parameterTypes)
        assertTrue(attribute.isReadOnly, "$targetClass.$methodName should be read-only")
    }

    private fun assertReadWrite(targetClass: Class<*>, methodName: String, vararg parameterTypes: Class<*>) {
        val attribute = transactionAttribute(targetClass, methodName, *parameterTypes)
        assertFalse(attribute.isReadOnly, "$targetClass.$methodName should be read-write")
    }

    private fun transactionAttribute(targetClass: Class<*>, methodName: String, vararg parameterTypes: Class<*>) =
        assertNotNull(
            transactionAttributes.getTransactionAttribute(
                targetClass.getMethod(methodName, *parameterTypes),
                targetClass,
            ),
            "$targetClass.$methodName should declare transaction metadata",
        )
}
