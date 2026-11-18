package dev.usbharu.toloidp.security

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Tag("unit")
class JtiDenylistEntryTests {
    @Test
    fun exposesJtiAsThePersistableId() {
        val entry = JtiDenylistEntry("jti-1", Instant.parse("2030-01-01T00:00:00Z"))

        assertEquals("jti-1", entry.jti)
        assertEquals("jti-1", entry.getId())
    }

    @Test
    fun isNewFollowsTheExplicitEntityFlag() {
        val entry = JtiDenylistEntry("jti-1", Instant.parse("2030-01-01T00:00:00Z"))

        assertFalse(entry.isNewEntity)
        assertFalse(entry.isNew())
        entry.isNewEntity = true
        assertTrue(entry.isNewEntity)
        assertTrue(entry.isNew())
    }
}
