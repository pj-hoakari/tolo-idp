FROM eclipse-temurin:24-jdk AS build
ARG RELEASE_VERSION=0.0.1-SNAPSHOT
WORKDIR /workspace

COPY gradlew settings.gradle.kts build.gradle.kts ./
COPY gradle gradle
COPY src src

RUN chmod +x gradlew && ./gradlew bootJar -PimageRuntime=jvm -PreleaseVersion=${RELEASE_VERSION} -x test --no-daemon

FROM eclipse-temurin:24-jre
WORKDIR /app

COPY --from=build /workspace/build/libs/tolo-idp-*.jar /app/app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
