package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:code-claim;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"])
class JdbcCodeClaimStoreTests(
    @Autowired private val claims: CodeClaimStore,
) {
    @Test
    fun aCodeCanOnlyBeClaimedOnceUntilReleased() {
        val code = "claim-" + UUID.randomUUID()
        val expiresAt = Instant.now().plusSeconds(60)

        assertEquals(CodeClaimResult.CLAIMED, claims.claim(code, expiresAt))
        assertEquals(CodeClaimResult.IN_PROGRESS, claims.claim(code, expiresAt))
        claims.complete(code)
        assertEquals(CodeClaimResult.COMPLETED, claims.claim(code, expiresAt))

        claims.release(code)
        assertEquals(CodeClaimResult.CLAIMED, claims.claim(code, expiresAt))
        claims.release(code)
    }
}
