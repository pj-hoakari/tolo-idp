package dev.usbharu.toloidp.config

import org.junit.jupiter.api.Tag
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.springframework.core.io.FileSystemResource
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.util.Base64
import kotlin.io.path.createTempFile
import kotlin.io.path.createTempDirectory

@Tag("unit")
class SecurityConfigJwkTests {
    private val securityConfig = SecurityConfig()

    @Test
    fun rejectsMissingConfiguredKeyUnlessEphemeralIsExplicitlyAllowed() {
        val exception = assertFailsWith<IllegalStateException> {
            securityConfig.jwkSource(IdpProperties())
        }

        assertEquals(
            "Configure tolo-idp.jwk.private-key-pem or tolo-idp.jwk.private-key-location, " +
                "or explicitly set tolo-idp.jwk.allow-ephemeral=true for dev/test.",
            exception.message,
        )
    }

    @Test
    fun readsPkcs8PrivateKeyFromPemProperty() {
        val pem = testPrivateKeyPem()

        val jwk = securityConfig.jwkSource(
            IdpProperties(
                jwk = IdpProperties.Jwk(
                    privateKeyPem = pem,
                    keyId = "configured-key",
                ),
            ),
        ).firstJwk()

        assertEquals("configured-key", jwk.keyID)
        assertNotNull(jwk.toRSAKey().toRSAPublicKey())
        assertNotNull(jwk.toRSAKey().toRSAPrivateKey())
    }

    @Test
    fun readsPkcs8PrivateKeyFromLocationProperty() {
        val keyFile = createTempFile(prefix = "tolo-idp-test-key", suffix = ".pem")
        keyFile.writeText(testPrivateKeyPem())

        val jwk = securityConfig.jwkSource(
            IdpProperties(
                jwk = IdpProperties.Jwk(
                    privateKeyLocation = FileSystemResource(keyFile),
                    keyId = "file-key",
                ),
            ),
        ).firstJwk()

        assertEquals("file-key", jwk.keyID)
        assertNotNull(jwk.toRSAKey().toRSAPublicKey())
    }

    @Test
    fun rejectsMissingConfiguredKeyLocationWithoutFallingBackToEphemeralKey() {
        val missingKey = createTempDirectory(prefix = "tolo-idp-missing-key").resolve("missing.pem")

        val exception = assertFailsWith<IllegalStateException> {
            securityConfig.jwkSource(
                IdpProperties(
                    jwk = IdpProperties.Jwk(
                        privateKeyLocation = FileSystemResource(missingKey),
                        allowEphemeral = true,
                    ),
                ),
            )
        }

        assertEquals(
            "Configured tolo-idp.jwk.private-key-location does not exist: file [$missingKey]",
            exception.message,
        )
    }

    @Test
    fun derivesStableKeyIdFromConfiguredPublicKeyWhenKeyIdIsOmitted() {
        val pem = testPrivateKeyPem()
        val properties = IdpProperties(jwk = IdpProperties.Jwk(privateKeyPem = pem))

        val firstKid = securityConfig.jwkSource(properties).firstJwk().keyID
        val secondKid = securityConfig.jwkSource(properties).firstJwk().keyID

        assertEquals(firstKid, secondKid)
        assertTrue(firstKid.matches(Regex("[A-Za-z0-9_-]{43}")))
    }

    @Test
    fun usesConfiguredKeyIdForEphemeralKey() {
        val jwk = securityConfig.jwkSource(
            IdpProperties(jwk = IdpProperties.Jwk(allowEphemeral = true, keyId = "ephemeral-key")),
        ).firstJwk()

        assertEquals("ephemeral-key", jwk.keyID)
        assertNotNull(jwk.toRSAKey().toRSAPublicKey())
    }

    @Test
    fun generatesRandomKeyIdForEphemeralKey() {
        for (keyId in listOf(null, "", " ")) {
            val properties = IdpProperties(jwk = IdpProperties.Jwk(allowEphemeral = true, keyId = keyId))
            val first = securityConfig.jwkSource(properties).firstJwk().keyID
            val second = securityConfig.jwkSource(properties).firstJwk().keyID

            assertTrue(first.matches(Regex("[0-9a-f-]{36}")))
            assertNotEquals(first, second)
        }
    }

    private fun com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext>.firstJwk() =
        get(JWKSelector(JWKMatcher.Builder().build()), null).single()

    private fun testPrivateKeyPem(): String {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val privateKey = keyPairGenerator.generateKeyPair().private as RSAPrivateKey
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(privateKey.encoded)
        return """
            -----BEGIN PRIVATE KEY-----
            $encoded
            -----END PRIVATE KEY-----
        """.trimIndent()
    }
}
