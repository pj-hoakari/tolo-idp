# AGENTS.md

このリポジトリで作業するエージェント向けのガイドです。仕様の正本は [spec.md](spec.md) です。OAuth2 / 認可 / Token Exchange に関わる変更では、必ず `spec.md` を読んでから実装してください。

## Project

- プロジェクト名: `tolo-idp`
- 目的: マルチテナント環境向け OAuth2 / OpenID Connect Authorization Server
- 技術スタック:
  - Kotlin JVM `2.2.21`
  - Spring Boot `4.0.6`
  - Java toolchain `24`
  - Gradle Kotlin DSL
  - Spring Security OAuth2 Authorization Server
  - Spring Data JDBC / Flyway
  - Thymeleaf
  - H2 / SQLite JDBC
  - GraalVM Native Build Tools

## Source Of Truth

- OAuth2 マルチテナント・イベント単位 Token Exchange の仕様は `spec.md` を正とします。
- `AGENTS.md` に仕様本文を重複させないでください。仕様を変更する場合は `spec.md` を更新し、このファイルには作業上の注意だけを書いてください。
- `HELP.md` は Spring Initializr 由来の補助情報です。JVM バージョン、Gradle、Spring Boot、Native Image まわりの確認に使ってください。

## Build And Test

基本確認:

```bash
./gradlew test
./gradlew build
```

開発環境は `dev-jvm` / `dev-native`、本番環境は `production` です。起動手順は `README.md` を参照してください。JVM 開発環境はホスト側の Gradle 実行なしで起動できます。

```bash
docker compose -f docker-compose.dev-jvm.yaml up -d --build
```

Native Image 関連:

```bash
./gradlew nativeCompile
./gradlew nativeTest
./gradlew bootBuildImage
```

注意:

- `HELP.md` にある通り、Kotlin が Java 25 に未対応のため JVM level は `24` です。Java 25 へ上げないでください。
- Native Image は GraalVM 25+ が必要です。
- Docker が必要な `bootBuildImage` は、ローカル環境の Docker 状態に依存します。

## Repository Layout

- `spec.md`: OAuth2 マルチテナント・イベント単位 Token Exchange 仕様
- `HELP.md`: 生成時の補助ドキュメント
- `build.gradle.kts`: Gradle / Spring Boot / Kotlin 設定
- `settings.gradle.kts`: root project name
- `src/main/kotlin/dev/usbharu/toloidp/ToloIdpApplication.kt`: Spring Boot entry point
- `src/main/resources/application.yaml`: アプリケーション設定
- `src/test/kotlin/dev/usbharu/toloidp/ToloIdpApplicationTests.kt`: context load test

Kotlin の package root は `dev.usbharu.toloidp` です。新規コードはこの package 配下に配置してください。

## Coding Guidelines

- Kotlin で実装し、既存の Spring Boot / Spring Security / Spring Data JDBC の流儀に合わせてください。
- `build.gradle.kts` の依存関係は必要最小限にしてください。
- 認可、Token Exchange、JWT claim、監査ログ、入力検証はセキュリティ境界です。変更時は仕様に対応するテストを追加してください。
- セキュリティ境界に関わる処理では、暗黙の補正や寛容な解釈を避けてください。
- tenant / event / membership の存在や権限に関する詳細を外部エラーへ漏らさないでください。
- access token、refresh token、client secret、authorization code、password をログへ出力しないでください。

## Token Exchange Implementation Checklist

詳細は `spec.md` を参照してください。実装時は最低限、次を守ってください。

- Token Exchange の段階は `login -> tenant_access -> event_access` のみ許可する。
- `tenant_id` / `event_id` は `scope` に含めず、`resource` から解釈して JWT claim として発行する。
- `x_tenant_id` / `x_event_id` は使わない。
- requested scope を暗黙に縮小しない。許可外 scope は `invalid_scope` にする。
- Token Exchange は confidential client のみ許可する。public client からの Token Exchange は禁止する。
- `audience` は必須、client ごとの許可対象に含まれることを検証する。
- 1 access token に複数 audience を入れない。
- Access Token は JWT とし、Opaque Token と Introspection は使わない。
- `role` / `tenant_role` / `event_role` を JWT claim に入れない。
- Resource Server 側の最終認可を省略しない。
- Token Exchange の成功・失敗を監査ログに残す。

## Resource And ID Handling

`resource` と ID の扱いは `spec.md` に従ってください。特に次を守ってください。

- tenant resource と event resource の path 形式を明示的に検証する。
- `resource` は絶対 URI、`https` scheme、許可済み host、許可済み path pattern を要求する。
- tenant / event の存在、有効性、所属関係、subject user のアクセス可否を検証する。
- `tenantId` / `eventId` は `^[A-Za-z0-9_-]{1,64}$` に限定する。
- ID 入力値に `trim`、大文字小文字変換、Unicode 正規化を行わない。

## Error Policy

外部レスポンスは `spec.md` のエラー方針に合わせてください。

- Token Exchange 不許可: `invalid_grant`
- scope 不許可: `invalid_scope`
- audience / resource 不許可: `invalid_target`
- リクエスト形式不正: `invalid_request`

tenant / event / membership の詳細な失敗理由は監査ログなど内部向けに留め、外部レスポンスではまとめて扱ってください。

## Open Design Items

`spec.md` の未確定事項は、実装時に決め打ちしすぎず、設定や境界を分けて変更しやすくしてください。
