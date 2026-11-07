package dev.usbharu.toloidp.ratelimit

import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CredentialRequestTests {
    @Test
    fun jsonMediaTypesAreMatchedCaseInsensitivelyIncludingVendorJson() {
        assertTrue(isJsonCredential("application/json"))
        assertTrue(isJsonCredential("Application/JSON"))
        assertTrue(isJsonCredential("application/vnd.api+json"))
        assertTrue(isJsonCredential("application/problem+json;charset=UTF-8"))
        assertFalse(isJsonCredential("text/plain"))
        assertFalse(isJsonCredential("application/xml"))
        assertFalse(isJsonCredential(null))
    }

    @Test
    fun decodedCredentialPathIsRecognized() {
        assertTrue(isCredentialPath(MockHttpServletRequest("POST", "/api/login")))
        assertTrue(isCredentialPath(MockHttpServletRequest("POST", "/api/signup")))
        assertTrue(isCredentialPath(MockHttpServletRequest("POST", "/api/%6Cogin")))
        assertFalse(isCredentialPath(MockHttpServletRequest("POST", "/api/other")))
    }
}
