import org.springframework.boot.gradle.tasks.aot.ProcessAot
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "4.0.6"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.graalvm.buildtools.native") version "1.1.18" apply false
    id("org.jetbrains.kotlinx.kover") version "0.9.11"
}

group = "dev.usbharu"
version = providers.gradleProperty("releaseVersion").getOrElse("0.0.1-SNAPSHOT")
description = "tolo-idp"

val imageRuntime = providers.gradleProperty("imageRuntime").getOrElse("native")
require(imageRuntime in setOf("jvm", "native")) { "imageRuntime must be jvm or native" }
if (imageRuntime == "native") {
    apply(plugin = "org.graalvm.buildtools.native")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(24)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("com.google.cloud:spring-cloud-gcp-dependencies:8.3.1"))
    developmentOnly("org.springframework.boot:spring-boot-h2console")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-flyway")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("com.google.cloud:spring-cloud-gcp-starter-logging")
    implementation("com.bucket4j:bucket4j_jdk17-core:8.22.0")
    implementation("com.bucket4j:bucket4j_jdk17-lettuce:8.22.0")
    implementation("io.lettuce:lettuce-core")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("com.nimbusds:nimbus-jose-jwt")
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity6")
    implementation("tools.jackson.module:jackson-module-kotlin")
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    developmentOnly("com.h2database:h2")
    runtimeOnly("org.flywaydb:flyway-database-postgresql")
    runtimeOnly("org.postgresql:postgresql")
    runtimeOnly("org.xerial:sqlite-jdbc")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    testImplementation("org.springframework.boot:spring-boot-starter-actuator-test")
    testImplementation("org.springframework.boot:spring-boot-starter-data-jdbc-test")
    testImplementation("org.springframework.boot:spring-boot-starter-flyway-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-oauth2-authorization-server-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-test")
    testImplementation("org.springframework.boot:spring-boot-starter-thymeleaf-test")
    testImplementation("org.springframework.boot:spring-boot-starter-validation-test")
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    testImplementation("org.testcontainers:testcontainers-postgresql")
    testRuntimeOnly("com.h2database:h2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

// Classes annotated with @SpringBootTest. Keep this list in sync when adding a new
// Spring-context test. `-PunitOnly` excludes them so the fast CI unit-test job does not
// start a context or run database-backed integration tests.
val springContextTests = setOf(
    "dev.usbharu.toloidp.ToloIdpApplicationTests",
    "dev.usbharu.toloidp.audit.AuditServiceTests",
    "dev.usbharu.toloidp.client.ClientPolicySettingsTests",
    "dev.usbharu.toloidp.config.ClientPolicyConfigurationTests",
    "dev.usbharu.toloidp.config.CorsConfigTests",
    "dev.usbharu.toloidp.config.RegisteredClientConfigurationSynchronizerTests",
    "dev.usbharu.toloidp.config.SeedDataRunnerTests",
    "dev.usbharu.toloidp.ratelimit.ForwardedHeadersFromInternalProxyTests",
    "dev.usbharu.toloidp.ratelimit.ForwardedHeadersFromUntrustedPeerTests",
    "dev.usbharu.toloidp.ratelimit.RateLimitFilterTests",
    "dev.usbharu.toloidp.ratelimit.RateLimitIdentityExtractorTests",
    "dev.usbharu.toloidp.relation.CachedRelationServiceTests",
    "dev.usbharu.toloidp.relation.RelationCacheControllerSecurityTests",
    "dev.usbharu.toloidp.relation.RelationLookupTimeoutTests",
    "dev.usbharu.toloidp.security.AuthorizationRequestParameterSplitTests",
    "dev.usbharu.toloidp.security.AuthorizationServerSurfaceTests",
    "dev.usbharu.toloidp.security.ConfiguredClientTokenFlowTests",
    "dev.usbharu.toloidp.security.DeviceAuthorizationFlowTests",
    "dev.usbharu.toloidp.security.DeviceAuthorizationPostgresFlowTests",
    "dev.usbharu.toloidp.security.JdbcCodeClaimStoreTests",
    "dev.usbharu.toloidp.security.LoginChallengeFlowTests",
    "dev.usbharu.toloidp.security.LoginChallengesTests",
    "dev.usbharu.toloidp.security.LoginControllerTests",
    "dev.usbharu.toloidp.security.OidcRequestContractTests",
    "dev.usbharu.toloidp.security.RefreshAwareAuthorizationServiceTests",
    "dev.usbharu.toloidp.security.RegistrationFlowTests",
    "dev.usbharu.toloidp.security.RpInitiatedLogoutTests",
    "dev.usbharu.toloidp.security.SecurityComponentTests",
    "dev.usbharu.toloidp.security.SessionCookieTests",
    "dev.usbharu.toloidp.security.SignupConcurrencyTests",
    "dev.usbharu.toloidp.security.TenantScopedUserFlowTests",
    "dev.usbharu.toloidp.security.TokenExchangeEndpointTests",
    "dev.usbharu.toloidp.security.TokenIntrospectionClientRemovalTests",
    "dev.usbharu.toloidp.security.TokenIntrospectionEndpointTests",
    "dev.usbharu.toloidp.security.TokenRevocationEndpointTests",
    "dev.usbharu.toloidp.user.IdpUserDetailsManagerTests",
    "dev.usbharu.toloidp.user.UserRegistrationServiceTests",
)

tasks.withType<Test> {
    useJUnitPlatform()
    if (providers.gradleProperty("unitOnly").isPresent) {
        filter {
            springContextTests.forEach { excludeTestsMatching(it) }
        }
    }
}

tasks.withType<ProcessAot>().configureEach {
    // Use production bean conditions and the explicit PostgreSQL dialect bean
    // so JDBC query pre-generation does not require a running database.
    args("--spring.profiles.active=production")
}

tasks.named<BootBuildImage>("bootBuildImage") {
    // JVM containers are built by Dockerfile. Buildpacks always produces Native.
    doFirst {
        require(imageRuntime == "native") { "bootBuildImage requires imageRuntime=native; use Dockerfile for JVM" }
    }
    builder.set("paketobuildpacks/builder-noble-java-tiny:latest")
    imageName.set("tolo-idp:${project.version}")
    environment.put("BP_JVM_VERSION", "25")
    environment.put("BP_NATIVE_IMAGE", "true")
    val extraNativeArguments = providers.gradleProperty("nativeImageExtraBuildArguments").getOrElse("")
    environment.put("BP_NATIVE_IMAGE_BUILD_ARGUMENTS", "-march=compatibility $extraNativeArguments".trim())
}

kover {
    reports {
        filters {
            includes {
                classes("dev.usbharu.toloidp.*")
            }
            excludes {
                classes(
                    "dev.usbharu.toloidp.ToloIdpApplication",
                    "dev.usbharu.toloidp.ToloIdpApplicationKt",
                    "dev.usbharu.toloidp.*__*",
                    "dev.usbharu.toloidp.config.*",
                )
            }
        }
        verify {
            rule {
                minBound(90)
            }
        }
    }
}
