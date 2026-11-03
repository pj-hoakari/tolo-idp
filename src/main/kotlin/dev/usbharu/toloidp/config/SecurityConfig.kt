package dev.usbharu.toloidp.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.ratelimit.RateLimitFilter
import dev.usbharu.toloidp.scope.ScopePolicy
import dev.usbharu.toloidp.scope.IdpScopes
import dev.usbharu.toloidp.security.JtiDenylistRepository
import dev.usbharu.toloidp.security.SpecTokenRevocationAuthenticationProvider
import dev.usbharu.toloidp.security.SpecTokenExchangeAuthenticationProvider
import dev.usbharu.toloidp.security.TenantAuthorizationValidator
import dev.usbharu.toloidp.security.TenantAwareAuthorizationRequestConverter
import dev.usbharu.toloidp.security.ToloJwtCustomizer
import dev.usbharu.toloidp.security.OidcAuthenticationRequestValidator
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.HttpHeaders
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.jackson.SecurityJacksonModules
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter
import org.springframework.security.authentication.AuthenticationProvider
import dev.usbharu.toloidp.user.IdpUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.security.web.context.SecurityContextHolderFilter
import tools.jackson.databind.JacksonModule
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator
import javax.sql.DataSource
import java.time.Clock
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import java.util.UUID
import java.util.function.Consumer

/**
 * IDP の Spring Security / Spring Authorization Server 構成を束ねる設定クラス。
 *
 * filter chain は個別性の高い内部 endpoint から一般 application endpoint の順に並べる。
 * このクラスの Authorization Server 関連 Bean は、IDP 仕様でより厳密な Token Exchange /
 * JWT / resource / audience / error handling が必要な箇所でデフォルト挙動を置き換える。
 */
@Configuration
@EnableConfigurationProperties(IdpProperties::class)
class SecurityConfig {
    /**
     * 内部 relation-membership cache purge API を x509 認証と証明書 subject の許可リストで保護する。
     */
    @Bean
    @Order(0)
    fun relationCacheSecurityFilterChain(
        http: HttpSecurity,
        properties: IdpProperties,
        rateLimitFilter: ObjectProvider<RateLimitFilter>,
    ): SecurityFilterChain {
        http.securityMatcher("/internal/relation-cache/**")
            .authorizeHttpRequests {
                it.anyRequest().hasRole("RELATION_CACHE_ADMIN")
            }
            .x509 {
                it.authenticationUserDetailsService { token: PreAuthenticatedAuthenticationToken ->
                    val subject = token.name
                    val user = User.withUsername(subject).password("")
                    if (subject in properties.relation.cache.adminSubjects) {
                        user.roles("RELATION_CACHE_ADMIN")
                    } else {
                        user.roles("RELATION_CACHE_DENIED")
                    }
                    user.build()
                }
            }
            .csrf { it.disable() }
            .formLogin { it.disable() }
            .logout { it.disable() }
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            }
        addRateLimitFilter(http, rateLimitFilter)
        return http.build()
    }

    /**
     * Authorization Server endpoint を構成し、この IDP でセキュリティ上重要な拡張点を差し替える。
     *
     * Authorization Code endpoint では tenant resource を注入・検証し、token endpoint では
     * `spec.md` の tenant-access から event-access への Token Exchange に
     * [SpecTokenExchangeAuthenticationProvider] を使う。
     */
    @Bean
    @Order(2)
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
        registeredClientRepository: RegisteredClientRepository,
        authorizationService: OAuth2AuthorizationService,
        authorizationConsentService: OAuth2AuthorizationConsentService,
        users: IdpUserDetailsManager,
        oidcRequests: OidcAuthenticationRequestValidator,
        tokenGenerator: OAuth2TokenGenerator<OAuth2Token>,
        resourceParser: ResourceParser,
        relationService: RelationService,
        scopePolicy: ScopePolicy,
        @Qualifier("specTokenExchangeAuthenticationProvider")
        specTokenExchangeAuthenticationProvider: AuthenticationProvider,
        @Qualifier("specTokenRevocationAuthenticationProvider")
        specTokenRevocationAuthenticationProvider: AuthenticationProvider,
        settings: AuthorizationServerSettings,
        rateLimitFilter: ObjectProvider<RateLimitFilter>,
    ): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
        http.with(authorizationServerConfigurer) { authorizationServer ->
            authorizationServer
                .oidc { oidc ->
                    oidc.userInfoEndpoint { endpoint ->
                        endpoint.errorResponseHandler { _, response, exception ->
                            val error = (exception as? OAuth2AuthenticationException)?.error
                                ?: OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN)
                            val status = when (error.errorCode) {
                                OAuth2ErrorCodes.INVALID_TOKEN -> HttpStatus.UNAUTHORIZED
                                OAuth2ErrorCodes.INSUFFICIENT_SCOPE -> HttpStatus.FORBIDDEN
                                else -> HttpStatus.BAD_REQUEST
                            }
                            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"${error.errorCode}\"")
                            val httpResponse = ServletServerHttpResponse(response)
                            httpResponse.setStatusCode(status)
                            OAuth2ErrorHttpMessageConverter().write(OAuth2Error(error.errorCode), null, httpResponse)
                        }
                        endpoint.userInfoMapper { context ->
                            val subject = context.authorization.getToken(OidcIdToken::class.java)!!.token.subject
                            val user = try {
                                users.loadUserById(subject)
                            } catch (_: UsernameNotFoundException) {
                                throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN)
                            }
                            if (!user.isEnabled) throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN)
                            val claims = OidcUserInfo.builder().subject(subject)
                            if (IdpScopes.PROFILE in context.accessToken.scopes) {
                                claims.preferredUsername(user.username)
                            }
                            claims.build()
                        }
                    }
                    oidc.providerConfigurationEndpoint { providerConfigurationEndpoint ->
                        providerConfigurationEndpoint.providerConfigurationCustomizer { metadata ->
                            metadata.claims(discoveryMetadataClaimsCustomizer())
                            metadata.claim("request_parameter_supported", false)
                            metadata.claim("request_uri_parameter_supported", false)
                            metadata.claim("response_modes_supported", listOf("query"))
                        }
                    }
                }
                .registeredClientRepository(registeredClientRepository)
                .authorizationService(authorizationService)
                .authorizationConsentService(authorizationConsentService)
                .authorizationServerSettings(settings)
                .tokenGenerator(tokenGenerator)
                .authorizationServerMetadataEndpoint { metadataEndpoint ->
                    metadataEndpoint.authorizationServerMetadataCustomizer { metadata ->
                        metadata.claims(discoveryMetadataClaimsCustomizer())
                    }
                }
                .authorizationEndpoint { authorizationEndpoint ->
                authorizationEndpoint.authorizationRequestConverters { converters ->
                    converters.removeIf { it is OAuth2AuthorizationCodeRequestAuthenticationConverter }
                    converters.add(0, TenantAwareAuthorizationRequestConverter(resourceParser))
                }
                authorizationEndpoint.authenticationProviders { providers ->
                    providers.filterIsInstance<OAuth2AuthorizationCodeRequestAuthenticationProvider>()
                        .forEach {
                            it.setAuthenticationValidator(
                                TenantAuthorizationValidator(
                                    users,
                                    resourceParser,
                                    relationService,
                                    scopePolicy,
                                    oidcRequests,
                                ),
                            )
                        }
                }
            }
                .tokenEndpoint { tokenEndpoint ->
                tokenEndpoint.errorResponseHandler(tokenEndpointErrorResponseHandler())
                tokenEndpoint.authenticationProviders { providers ->
                    providers.removeIf { it is OAuth2TokenExchangeAuthenticationProvider }
                    providers.add(specTokenExchangeAuthenticationProvider)
                }
            }
                .tokenIntrospectionEndpoint { introspectionEndpoint ->
                    introspectionEndpoint.errorResponseHandler(oauth2CodeOnlyErrorResponseHandler())
                    introspectionEndpoint.introspectionResponseHandler(tokenIntrospectionResponseHandler())
                    introspectionEndpoint.authenticationProviders { providers ->
                        providers.replaceAll { provider ->
                            if (provider is OAuth2TokenIntrospectionAuthenticationProvider) {
                                tokenIntrospectionClientGuard(provider)
                            } else {
                                provider
                            }
                        }
                    }
                }
                .tokenRevocationEndpoint { revocationEndpoint ->
                    revocationEndpoint.errorResponseHandler(oauth2CodeOnlyErrorResponseHandler())
                    revocationEndpoint.authenticationProviders { providers ->
                        providers.removeIf { it is OAuth2TokenRevocationAuthenticationProvider }
                        providers.add(specTokenRevocationAuthenticationProvider)
                    }
                }
        }

        http.securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .csrf { it.ignoringRequestMatchers(authorizationServerConfigurer.endpointsMatcher) }
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            }
            .formLogin { it.disable() }
        addRateLimitFilter(http, rateLimitFilter)
        return http.build()
    }

    private fun discoveryMetadataClaimsCustomizer(): Consumer<MutableMap<String, Any>> =
        Consumer { claims ->
            claims[OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED] = listOf(
                AuthorizationGrantType.AUTHORIZATION_CODE.value,
                AuthorizationGrantType.REFRESH_TOKEN.value,
                AuthorizationGrantType.TOKEN_EXCHANGE.value,
            )
            claims[OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED] = IdpScopes.SUPPORTED.toList()
            claims[OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED] =
                listOf(
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST.value,
                )
            claims[OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED] =
                listOf(
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST.value,
                )
            claims[OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED] =
                listOf(
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST.value,
                )
        }

    /**
     * Authorization Server 外の application endpoint を保護する。
     */
    @Bean
    @Order(3)
    fun applicationSecurityFilterChain(
        http: HttpSecurity,
        rateLimitFilter: ObjectProvider<RateLimitFilter>,
    ): SecurityFilterChain {
        http.authorizeHttpRequests {
            it.requestMatchers("/actuator/health").permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/api/login", "/api/logout").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/login").permitAll()
                .anyRequest().authenticated()
        }
            .cors { }
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            }
            .formLogin { it.disable() }
            .logout { it.disable() }
            .csrf { it.disable() }
        addRateLimitFilter(http, rateLimitFilter)
        return http.build()
    }

    /**
     * Spring Security の Jackson module を使って framework 型を保持しつつ、OAuth2 registered client を
     * JDBC に保存する repository。
     */
    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate): RegisteredClientRepository {
        val jsonMapper = registeredClientJsonMapper()
        return JdbcRegisteredClientRepository(jdbcTemplate).apply {
            setRegisteredClientRowMapper(
                JdbcRegisteredClientRepository.JsonMapperRegisteredClientRowMapper(jsonMapper),
            )
            setRegisteredClientParametersMapper(
                JdbcRegisteredClientRepository.JsonMapperRegisteredClientParametersMapper(jsonMapper),
            )
        }
    }

    private fun registeredClientJsonMapper(): JsonMapper {
        val typeValidatorBuilder = BasicPolymorphicTypeValidator.builder()
            .allowIfSubType(Long::class.javaObjectType)
            .allowIfSubType("java.util.")
            .allowIfSubType("java.time.")
            .allowIfSubType("org.springframework.security.oauth2.")
        val securityModules: List<JacksonModule> =
            SecurityJacksonModules.getModules(SecurityConfig::class.java.classLoader, typeValidatorBuilder)
        return JsonMapper.builder()
            .addModules(securityModules)
            .build()
    }

    private fun tokenEndpointErrorResponseHandler(): AuthenticationFailureHandler {
        return AuthenticationFailureHandler { _, response, exception ->
            val error = tokenEndpointError(exception)
            writeOAuth2Error(response, error)
        }
    }

    private fun tokenEndpointError(exception: AuthenticationException): OAuth2Error =
        if (exception is OAuth2AuthenticationException &&
            exception.error.errorCode == OAuth2ErrorCodes.INVALID_REQUEST &&
            exception.error.description?.contains(OAuth2ParameterNames.RESOURCE) == true
        ) {
            OAuth2Error("invalid_target")
        } else if (exception is OAuth2AuthenticationException &&
            exception.error.errorCode == OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE
        ) {
            OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)
        } else if (exception is OAuth2AuthenticationException) {
            OAuth2Error(exception.error.errorCode)
        } else {
            OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)
        }

    private fun oauth2CodeOnlyErrorResponseHandler(): AuthenticationFailureHandler =
        AuthenticationFailureHandler { _, response, exception ->
            val error = if (exception is OAuth2AuthenticationException) {
                OAuth2Error(exception.error.errorCode)
            } else {
                OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)
            }
            writeOAuth2Error(response, error)
        }

    private fun writeOAuth2Error(response: jakarta.servlet.http.HttpServletResponse, error: OAuth2Error) {
        val converter: HttpMessageConverter<OAuth2Error> = OAuth2ErrorHttpMessageConverter()
        val httpResponse = ServletServerHttpResponse(response)
        httpResponse.setStatusCode(HttpStatus.BAD_REQUEST)
        converter.write(error, null, httpResponse)
    }

    private fun tokenIntrospectionClientGuard(delegate: AuthenticationProvider): AuthenticationProvider =
        object : AuthenticationProvider {
            override fun authenticate(authentication: Authentication): Authentication? {
                val client = (authentication.principal as? OAuth2ClientAuthenticationToken)
                    ?.takeIf { it.isAuthenticated }
                    ?.registeredClient
                    ?: return delegate.authenticate(authentication)
                val policy = ClientPolicy.from(client)
                if (policy == null || policy.clientType != ClientType.CONFIDENTIAL || !policy.tokenIntrospectionAllowed) {
                    throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT))
                }
                return delegate.authenticate(authentication)
            }

            override fun supports(authentication: Class<*>): Boolean = delegate.supports(authentication)
        }

    private fun tokenIntrospectionResponseHandler(): AuthenticationSuccessHandler {
        val converter = OAuth2TokenIntrospectionHttpMessageConverter()
        return AuthenticationSuccessHandler { _, response, authentication ->
            val tokenIntrospection = authentication as OAuth2TokenIntrospectionAuthenticationToken
            val filteredClaims = tokenIntrospection.tokenClaims.claims
                .filterKeys { it in INTROSPECTION_RESPONSE_CLAIMS }
            val filtered = OAuth2TokenIntrospection.withClaims(filteredClaims).build()
            converter.write(filtered, null, ServletServerHttpResponse(response))
        }
    }

    private fun addRateLimitFilter(
        http: HttpSecurity,
        rateLimitFilter: ObjectProvider<RateLimitFilter>,
    ) {
        rateLimitFilter.ifAvailable {
            http.addFilterAfter(it, SecurityContextHolderFilter::class.java)
        }
    }

    /**
     * 発行済み authorization を永続化する。
     *
     * Token Exchange で subject token を検証するため、生成済み JWT metadata も保持する。
     */
    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationService =
        JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)

    /**
     * registered client の Authorization Code consent を永続化する。
     */
    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationConsentService =
        JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)

    /**
     * Spring Authorization Server のデフォルト Token Exchange 挙動ではなく、プロジェクト仕様を強制する
     * Token Exchange provider。
     */
    @Bean
    fun specTokenExchangeAuthenticationProvider(
        users: IdpUserDetailsManager,
        authorizationService: OAuth2AuthorizationService,
        tokenGenerator: OAuth2TokenGenerator<OAuth2Token>,
        resourceParser: ResourceParser,
        relationService: RelationService,
        scopePolicy: ScopePolicy,
        jtiDenylistRepository: JtiDenylistRepository,
        auditService: AuditService,
        clock: Clock,
    ): SpecTokenExchangeAuthenticationProvider =
        SpecTokenExchangeAuthenticationProvider(
            users,
            authorizationService,
            tokenGenerator,
            resourceParser,
            relationService,
            scopePolicy,
            jtiDenylistRepository,
            auditService,
            clock,
        )

    /**
     * RFC 7009 endpoint で Refresh Token の無効化と JWT access token の jti denylist 登録を行う。
     */
    @Bean
    fun specTokenRevocationAuthenticationProvider(
        authorizationService: OAuth2AuthorizationService,
        jtiDenylistRepository: JtiDenylistRepository,
        auditService: AuditService,
        clock: Clock,
        jwtDecoder: JwtDecoder,
        properties: IdpProperties,
    ): AuthenticationProvider =
        SpecTokenRevocationAuthenticationProvider(
            authorizationService,
            jtiDenylistRepository,
            auditService,
            clock,
            jwtDecoder,
            properties.issuer,
        )

    @Bean
    fun oidcAuthenticationRequestValidator(
        jwkSource: JWKSource<SecurityContext>, properties: IdpProperties, clock: Clock,
    ): OidcAuthenticationRequestValidator {
        val decoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource) as NimbusJwtDecoder
        // A previously issued, expired ID Token can still identify the requested user.
        decoder.setJwtValidator(JwtIssuerValidator(properties.issuer))
        return OidcAuthenticationRequestValidator(decoder, clock)
    }

    /**
     * 設定された issuer を Authorization Server metadata と JWT claim 生成へ反映する。
     */
    @Bean
    fun authorizationServerSettings(properties: IdpProperties): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().issuer(properties.issuer).build()

    /**
     * login API と Spring Security session 認証で使う JDBC ベースの user store。
     */
    @Bean
    fun userDetailsService(dataSource: DataSource, passwordEncoder: PasswordEncoder): IdpUserDetailsManager =
        IdpUserDetailsManager(dataSource, passwordEncoder)

    /**
     * 保存済み user password に `{bcrypt}` などの encoder id を含められる delegating password encoder。
     */
    @Bean
    fun passwordEncoder(): PasswordEncoder =
        PasswordEncoderFactories.createDelegatingPasswordEncoder()

    /**
     * tenant / event scope 認可で共有する role hierarchy。
     */
    @Bean
    fun roleHierarchy(): RoleHierarchy =
        ScopePolicy.defaultRoleHierarchy()

    /**
     * self-contained JWT access token の署名と検証に使う JWK source。
     *
     * production では安定した RSA private key を設定する。ephemeral key は明示的に許可された
     * development / test 用に限定する。
     */
    @Bean
    fun jwkSource(properties: IdpProperties): JWKSource<SecurityContext> {
        val rsaKey = configuredRsaKey(properties.jwk) ?: ephemeralRsaKey(properties.jwk)
        return ImmutableJWKSet(JWKSet(rsaKey))
    }

    private fun configuredRsaKey(properties: IdpProperties.Jwk): RSAKey? {
        val privateKeyPem = properties.privateKeyPem?.takeIf { it.isNotBlank() }
            ?: properties.privateKeyLocation?.let {
                if (!it.exists()) {
                    throw IllegalStateException("Configured tolo-idp.jwk.private-key-location does not exist: $it")
                }
                it.inputStream.bufferedReader().use { reader -> reader.readText() }
            }
            ?: return null
        val privateKey = parsePkcs8RsaPrivateKey(privateKeyPem)
        val publicKey = derivePublicKey(privateKey)
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(properties.keyId?.takeIf { it.isNotBlank() } ?: stableKeyId(publicKey))
            .build()
    }

    private fun ephemeralRsaKey(properties: IdpProperties.Jwk): RSAKey {
        if (!properties.allowEphemeral) {
            throw IllegalStateException(
                "Configure tolo-idp.jwk.private-key-pem or tolo-idp.jwk.private-key-location, " +
                    "or explicitly set tolo-idp.jwk.allow-ephemeral=true for dev/test.",
            )
        }
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        return RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(properties.keyId?.takeIf { it.isNotBlank() } ?: UUID.randomUUID().toString())
            .build()
    }

    private fun parsePkcs8RsaPrivateKey(pem: String): RSAPrivateKey {
        val base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .lines()
            .joinToString("") { it.trim() }
        val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64))
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec) as RSAPrivateKey
    }

    private fun derivePublicKey(privateKey: RSAPrivateKey): RSAPublicKey {
        val crtKey = privateKey as? RSAPrivateCrtKey
            ?: throw IllegalArgumentException("RSA private key must include CRT parameters to derive a public key")
        val keySpec = RSAPublicKeySpec(crtKey.modulus, crtKey.publicExponent)
        return KeyFactory.getInstance("RSA").generatePublic(keySpec) as RSAPublicKey
    }

    private fun stableKeyId(publicKey: RSAPublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    /**
     * 設定済み JWK source を使う JWT encoder。
     */
    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder =
        NimbusJwtEncoder(jwkSource)

    /**
     * Authorization Server の補助コードと test で使う JWT decoder。
     */
    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    /**
     * [ToloJwtCustomizer] で claim を付与する JWT と、Refresh Token を発行する generator。
     */
    @Bean
    fun tokenGenerator(
        jwtEncoder: JwtEncoder,
        jwtCustomizer: ToloJwtCustomizer,
    ): OAuth2TokenGenerator<OAuth2Token> {
        val jwtGenerator = JwtGenerator(jwtEncoder)
        jwtGenerator.setJwtCustomizer(jwtCustomizer)
        return DelegatingOAuth2TokenGenerator(jwtGenerator, OAuth2RefreshTokenGenerator())
    }

    /**
     * security service で共有する UTC clock。
     *
     * 有効期限と audit timestamp を test から制御しやすくする。
     */
    @Bean
    fun clock(): java.time.Clock = java.time.Clock.systemUTC()

    private companion object {
        val INTROSPECTION_RESPONSE_CLAIMS = setOf(
            "active",
            "client_id",
            "scope",
            "aud",
            "iss",
            "sub",
            "exp",
            "iat",
            "nbf",
            "jti",
            "token_type",
            "token_use",
            "resource",
            "tenant_id",
            "event_id",
        )
    }
}
