FROM eclipse-temurin:25-jdk@sha256:83f4a7fc27df94dcc7b8de04d14cbbba8da14406f921e966969c3b09000aa507 AS build
ARG RELEASE_VERSION=0.0.1-SNAPSHOT
WORKDIR /workspace

COPY gradlew settings.gradle.kts build.gradle.kts ./
COPY gradle gradle
COPY src src

RUN chmod +x gradlew && ./gradlew bootJar -PimageRuntime=jvm -PreleaseVersion=${RELEASE_VERSION} -x test --no-daemon

FROM eclipse-temurin:25-jre@sha256:ecdc0adb37bde1a281c4d245a3cd535004b1fc8322d560f5b09463b248c81df0
ENV TZ=UTC
ENV JAVA_TOOL_OPTIONS="-Duser.timezone=UTC"
WORKDIR /app

COPY --from=build /workspace/build/libs/tolo-idp-*.jar /app/app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
