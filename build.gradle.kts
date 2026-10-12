import org.springframework.boot.gradle.tasks.aot.ProcessAot
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "4.0.6"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.graalvm.buildtools.native") version "0.11.5" apply false
    id("org.jetbrains.kotlinx.kover") version "0.9.8"
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
    implementation(platform("com.google.cloud:spring-cloud-gcp-dependencies:8.0.4"))
    implementation("org.springframework.boot:spring-boot-h2console")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-flyway")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("com.google.cloud:spring-cloud-gcp-starter-logging")
    implementation("com.bucket4j:bucket4j_jdk17-core:8.19.0")
    implementation("com.bucket4j:bucket4j_jdk17-lettuce:8.19.0")
    implementation("io.lettuce:lettuce-core")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("com.nimbusds:nimbus-jose-jwt")
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity6")
    implementation("tools.jackson.module:jackson-module-kotlin")
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    runtimeOnly("com.h2database:h2")
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
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<ProcessAot>().configureEach {
    // AOT fixes bean conditions and JDBC mapping metadata at build time. Use the
    // production PostgreSQL setup, with a dedicated local database for processing.
    args(
        "--spring.profiles.active=prod",
        "--spring.data.jdbc.dialect=postgresql",
        "--spring.datasource.url=" + providers.gradleProperty("aotDatasourceUrl")
            .getOrElse("jdbc:postgresql://localhost:5432/tolo_idp"),
        "--spring.datasource.username=" + providers.gradleProperty("aotDatasourceUsername").getOrElse("tolo_idp"),
        "--spring.datasource.password=" + providers.gradleProperty("aotDatasourcePassword").getOrElse("tolo_idp"),
    )
}

tasks.named<BootBuildImage>("bootBuildImage") {
    // Java 24 is no longer included in the latest builder. Keep the last
    // compatible Java 24 builder for JVM images; Native uses the current GraalVM.
    builder.set(
        if (imageRuntime == "jvm") {
            "paketobuildpacks/builder-noble-java-tiny:0.0.62@sha256:8b1849c892ea08c5f1e39e5eec46cdcaf4c28c739f8251596fcca134cc399a3f"
        } else {
            "paketobuildpacks/builder-noble-java-tiny:latest"
        },
    )
    val imageRepository = "tolo-idp" + if (imageRuntime == "jvm") "-jvm" else ""
    imageName.set("$imageRepository:${project.version}")
    environment.put("BP_JVM_VERSION", if (imageRuntime == "native") "25" else "24")
    environment.put("BP_NATIVE_IMAGE", (imageRuntime == "native").toString())
    if (imageRuntime == "native") {
        environment.put("BP_NATIVE_IMAGE_BUILD_ARGUMENTS", "-march=compatibility")
    }
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
