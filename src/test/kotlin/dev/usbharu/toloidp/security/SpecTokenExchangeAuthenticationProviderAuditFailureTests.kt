package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopePolicy
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.doThrow
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.transaction.CannotCreateTransactionException
import org.springframework.transaction.TransactionSystemException
import java.time.Clock
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SpecTokenExchangeAuthenticationProviderAuditFailureTests {
    private val registeredClient = RegisteredClient.withId("client-id")
        .clientId("client-123")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
        .build()

    private val clientPrincipal = OAuth2ClientAuthenticationToken(
        registeredClient,
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        null,
    )

    private val tokenExchange = OAuth2TokenExchangeAuthenticationToken(
        "subject-token",
        ACCESS_TOKEN_TYPE,
        ACCESS_TOKEN_TYPE,
        clientPrincipal,
        null,
        null,
        setOf("https://api.example.com/tenants/tenant-a/events/event-1"),
        setOf("backend-api"),
        setOf("events.read"),
        emptyMap(),
    )

    @Test
    fun returnsOAuthErrorWhenTheAuditTransactionCannotStart() {
        val auditService = mock(AuditService::class.java)
        doThrow(CannotCreateTransactionException("audit store unavailable"))
            .`when`(auditService).record(anyAuditEvent())

        val error = assertFailsWith<OAuth2AuthenticationException> {
            provider(auditService).authenticate(tokenExchange)
        }

        assertEquals("invalid_request", error.error.errorCode)
        verify(auditService).record(anyAuditEvent())
    }

    @Test
    fun returnsOAuthErrorWhenTheAuditTransactionCommitFails() {
        val auditService = mock(AuditService::class.java)
        doThrow(TransactionSystemException("audit commit failed"))
            .`when`(auditService).record(anyAuditEvent())

        val error = assertFailsWith<OAuth2AuthenticationException> {
            provider(auditService).authenticate(tokenExchange)
        }

        assertEquals("invalid_request", error.error.errorCode)
        verify(auditService).record(anyAuditEvent())
    }

    private fun anyAuditEvent(): TokenAuditEvent =
        any(TokenAuditEvent::class.java) ?: TokenAuditEvent(result = "failure")

    private fun provider(auditService: AuditService): SpecTokenExchangeAuthenticationProvider =
        SpecTokenExchangeAuthenticationProvider(
            mock(IdpUserDetailsManager::class.java),
            mock(OAuth2AuthorizationService::class.java),
            mock(OAuth2TokenGenerator::class.java) as OAuth2TokenGenerator<OAuth2Token>,
            mock(ResourceParser::class.java),
            mock(RelationService::class.java),
            mock(ScopePolicy::class.java),
            mock(JtiDenylistRepository::class.java),
            auditService,
            Clock.systemUTC(),
            "observation-page",
            "observation-connection",
        )
}
