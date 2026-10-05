package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.logging.KeyValueLoggingEventEnhancer
import dev.usbharu.toloidp.relation.HttpRelationService
import org.springframework.aot.hint.BindingReflectionHintsRegistrar
import org.springframework.aot.hint.ExecutableMode
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.TypeReference
import org.springframework.aot.hint.registerType
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.jackson.SecurityJacksonModules
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Duration

class ToloIdpRuntimeHints : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        val reflection = hints.reflection()
        reflection
            .registerConstructor(
                KeyValueLoggingEventEnhancer::class.java.getDeclaredConstructor(),
                ExecutableMode.INVOKE,
            )
        reflection.registerType<OAuth2TokenFormat>(
            MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
        )
        reflection.registerType<SignatureAlgorithm>()
        reflection.registerType<Duration>()
        reflection.registerType<TokenAuditEvent>(
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
            MemberCategory.DECLARED_FIELDS,
        )

        BindingReflectionHintsRegistrar().registerReflectionHints(
            reflection,
            HttpRelationService.MembershipResponse::class.java,
            UsernamePasswordAuthenticationToken::class.java,
            SimpleGrantedAuthority::class.java,
            FactorGrantedAuthority::class.java,
            OAuth2AuthorizationRequest::class.java,
            OAuth2TokenFormat::class.java,
            SignatureAlgorithm::class.java,
        )

        // JDBC authorization persistence discovers Jackson 3 modules reflectively.
        // Preserve their constructors, plus the mix-ins and deserializers used to
        // restore the login principal and authorization request in Native images.
        SecurityJacksonModules.getModules(classLoader ?: javaClass.classLoader).forEach { module ->
            reflection.registerType(module.javaClass, MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS)
        }
        // Jackson resolves the concrete collection names embedded in JDBC JSON.
        listOf(
            "java.util.Collections\$UnmodifiableMap",
            "java.util.Collections\$UnmodifiableSet",
            "java.util.Collections\$UnmodifiableRandomAccessList",
            "java.util.Collections\$EmptyMap",
            "java.util.Collections\$EmptyList",
            "java.util.Collections\$SingletonList",
            "java.util.Arrays\$ArrayList",
        ).forEach { typeName -> reflection.registerType(TypeReference.of(typeName)) }
        listOf(
            "org.springframework.security.jackson.UsernamePasswordAuthenticationTokenMixin",
            "org.springframework.security.jackson.UsernamePasswordAuthenticationTokenDeserializer",
            "org.springframework.security.jackson.SimpleGrantedAuthorityMixin",
            "org.springframework.security.jackson.FactorGrantedAuthorityMixin",
            "org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationRequestMixin",
            "org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationRequestDeserializer",
            "org.springframework.security.oauth2.server.authorization.jackson.OAuth2TokenFormatMixin",
            "org.springframework.security.oauth2.server.authorization.jackson.JwsAlgorithmMixin",
        ).forEach { typeName ->
            reflection.registerType(
                TypeReference.of(typeName),
                MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                MemberCategory.INVOKE_DECLARED_METHODS,
                MemberCategory.DECLARED_FIELDS,
            )
        }

        val resources = hints.resources()
        resources.registerPattern("db/migration/**")
        resources.registerPattern("db/postgresql")
        resources.registerPattern("db/postgresql/**")
    }
}
