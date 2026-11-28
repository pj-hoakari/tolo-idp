import org.springframework.boot.gradle.tasks.aot.ProcessAot
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage
import java.math.BigDecimal

plugins {
    kotlin("jvm") version "2.4.21"
    kotlin("plugin.spring") version "2.4.21"
    id("org.springframework.boot") version "4.2.0"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.graalvm.buildtools.native") version "1.1.19" apply false
    id("org.jetbrains.kotlinx.kover") version "0.9.11"
    id("info.solidsoft.pitest") version "1.19.0"
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

tasks.withType<Test> {
    useJUnitPlatform {
        if (providers.gradleProperty("unitOnly").isPresent) {
            includeTags("unit")
        }
    }
}

val pitestSmoke = providers.gradleProperty("pitestSmoke").isPresent
val pitestTargetClassesOverride = providers.gradleProperty("pitestTargetClasses").orNull
val pitestTargetTestsOverride = providers.gradleProperty("pitestTargetTests").orNull

fun pitestGlobs(value: String): Set<String> =
    value.split(",").map(String::trim).filter(String::isNotEmpty).toSet()

pitest {
    // PIT 1.30.x supports Java 24 and the JUnit Platform 6 line.
    // gradle-pitest-plugin 1.19.0 can corrupt the JUnit 6 test classpath when it
    // adds the platform launcher itself, so use the existing testRuntimeOnly
    // junit-platform-launcher dependency instead.
    pitestVersion = "1.30.2"
    junit5PluginVersion = "1.2.3"
    addJUnitPlatformLauncher = false

    val smokeClasses = setOf(
        "dev.usbharu.toloidp.scope.*",
        "dev.usbharu.toloidp.resource.*",
        "dev.usbharu.toloidp.user.UserAccountRules*",
    )
    val smokeTests = setOf(
        "dev.usbharu.toloidp.scope.ScopePolicyTests",
        "dev.usbharu.toloidp.resource.ResourceParserTests",
        "dev.usbharu.toloidp.user.UserAccountRulesTests",
    )
    targetClasses = when {
        pitestTargetClassesOverride != null -> pitestGlobs(pitestTargetClassesOverride)
        pitestSmoke -> smokeClasses
        else -> setOf("dev.usbharu.toloidp.*")
    }
    targetTests = when {
        pitestTargetTestsOverride != null -> pitestGlobs(pitestTargetTestsOverride)
        pitestSmoke -> smokeTests
        // Only real test classes. This also excludes the Spring AOT-generated
        // *Tests__TestContext... classes that share the test runtime classpath.
        else -> setOf("dev.usbharu.toloidp.*Tests", "dev.usbharu.toloidp.*Test")
    }
    excludedClasses = setOf(
        "dev.usbharu.toloidp.ToloIdpApplication*",
        // Kotlin compiler-generated enum dispatch helpers.
        "dev.usbharu.toloidp.*\$WhenMappings",
        // Copies of inline function bodies; the definition is mutated instead.
        "dev.usbharu.toloidp.*\$\$inlined\$*",
    )
    excludedTestClasses = setOf(
        // Testcontainers based; keep it out of repeated mutation runs.
        "dev.usbharu.toloidp.security.DeviceAuthorizationPostgresFlowTests",
    )
    // Logging is not a security boundary. Include the project wrapper in addition
    // to PIT's defaults so its call sites are not reported as survivors.
    avoidCallsTo = setOf(
        "java.util.logging",
        "org.apache.log4j",
        "org.slf4j",
        "org.apache.commons.logging",
        "dev.usbharu.toloidp.logging",
    )

    outputFormats = setOf("HTML", "XML")
    timestampedReports = false
    reportDir.set(
        providers.gradleProperty("pitestReportDir")
            .flatMap { layout.buildDirectory.dir("reports/$it") }
            .orElse(layout.buildDirectory.dir("reports/pitest")),
    )
    threads = if (pitestSmoke) 1 else providers.gradleProperty("pitestThreads").orNull?.toInt() ?: 4
    timeoutConstInMillis = 10_000
    timeoutFactor = BigDecimal("1.5")
    jvmArgs = listOf("-Xmx1g")
    verbose = pitestSmoke || providers.gradleProperty("pitestVerbose").isPresent
    enableDefaultIncrementalAnalysis.set(providers.gradleProperty("pitestHistory").isPresent)
}

tasks.withType<JavaExec>().matching { it.name.startsWith("pitest") }.configureEach {
    javaLauncher.set(javaToolchains.launcherFor(java.toolchain))
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
