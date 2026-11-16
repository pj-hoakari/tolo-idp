package dev.usbharu.toloidp.config

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.util.TimeZone
import kotlin.test.assertEquals

@Tag("unit")
class UtcTimeZoneTests {
    @Test
    fun configuresTheJvmDefaultZoneAsUtc() {
        val original = TimeZone.getDefault()
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tokyo"))
            UtcTimeZone.configure()
            assertEquals("UTC", TimeZone.getDefault().id)
        } finally {
            TimeZone.setDefault(original)
        }
    }
}
