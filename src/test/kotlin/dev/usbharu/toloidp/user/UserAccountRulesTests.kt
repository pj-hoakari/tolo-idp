package dev.usbharu.toloidp.user

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UserAccountRulesTests {
    @Test
    fun acceptsTenantIdsWithinTheAllowedAlphabetAndLength() {
        assertTrue(UserAccountRules.isValidTenantId("a"))
        assertTrue(UserAccountRules.isValidTenantId("Tenant_09-A"))
        assertTrue(UserAccountRules.isValidTenantId("a".repeat(64)))
    }

    @ParameterizedTest
    @ValueSource(strings = ["", "tenant a", "テナント", "tenant/a", "tenant.a", "tenant:1"])
    fun rejectsTenantIdsOutsideTheAllowedAlphabet(value: String) {
        assertFalse(UserAccountRules.isValidTenantId(value))
    }

    @Test
    fun rejectsTenantIdsLongerThanSixtyFourCharacters() {
        assertFalse(UserAccountRules.isValidTenantId("a".repeat(65)))
    }

    @Test
    fun acceptsUsernamesWithoutWhitespaceUpToFiftyCharacters() {
        assertTrue(UserAccountRules.isValidUsername("user-123"))
        assertTrue(UserAccountRules.isValidUsername("ユーザー"))
        assertTrue(UserAccountRules.isValidUsername("a".repeat(50)))
    }

    @ParameterizedTest
    @ValueSource(strings = ["", "has space", "tab\tname", "line\nbreak"])
    fun rejectsUsernamesContainingWhitespace(value: String) {
        assertFalse(UserAccountRules.isValidUsername(value))
    }

    @ParameterizedTest
    @ValueSource(strings = ["\u0000", "\u001F", "\u007F"])
    fun rejectsUsernamesContainingControlCharacters(value: String) {
        assertFalse(UserAccountRules.isValidUsername(value))
    }

    @Test
    fun rejectsUsernamesLongerThanFiftyCharacters() {
        assertFalse(UserAccountRules.isValidUsername("a".repeat(51)))
    }

    @Test
    fun requiresPasswordsToHaveAtLeastEightCharacters() {
        assertFalse(UserAccountRules.isValidPassword("1234567"))
        assertTrue(UserAccountRules.isValidPassword("12345678"))
    }

    @Test
    fun measuresPasswordLengthInCharactersBeforeTheUtf8ByteLimit() {
        assertTrue(UserAccountRules.isValidPassword("あ".repeat(24)))
        assertFalse(UserAccountRules.isValidPassword("あ".repeat(25)))
    }

    @Test
    fun acceptsPasswordsUpToSeventyTwoUtf8Bytes() {
        assertTrue(UserAccountRules.isValidPassword("a".repeat(72)))
        assertFalse(UserAccountRules.isValidPassword("a".repeat(73)))
    }

    @Test
    fun acceptsOnlyCanonicalLowercaseUuidUserIds() {
        val userId = "71c68dc1-2c72-45ac-a191-1c47c1551011"

        assertTrue(UserAccountRules.isValidUserId(userId))
        assertFalse(UserAccountRules.isValidUserId(userId.uppercase()))
        assertFalse(UserAccountRules.isValidUserId(userId.replace("-", "")))
        assertFalse(UserAccountRules.isValidUserId("not-a-uuid"))
    }
}
