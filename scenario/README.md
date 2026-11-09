# シナリオテスト (runn)

[PR #9](https://github.com/pj-hoakari/tolo-idp/pull/9) の OIDC シナリオを、現在の開発環境と Token Exchange に対応させたものです。
[runn v1.10.0](https://github.com/k1LoW/runn/tree/v1.10.0) を Compose の `scenario` profile で実行します。

## 実行方法

リポジトリのルートで実行します。Docker と Compose が必要です。

まず [ルートの起動手順](../README.md) に従って `dev-jvm` または `dev-native` を起動します。

```bash
# JVM: Docker 内でソースからビルドして起動する。
docker compose -f docker-compose.dev-jvm.yaml up -d --build
docker compose -f docker-compose.dev-jvm.yaml --profile scenario run --rm --no-deps runn

# Native: 依存サービス → Native ビルド → app の順に起動する。
docker compose -f docker-compose.dev-native.yaml up -d --wait db redis relation-stub
./gradlew bootBuildImage
docker compose -f docker-compose.dev-native.yaml up -d app
docker compose -f docker-compose.dev-native.yaml --profile scenario run --rm --no-deps runn
```

各環境は IdP、PostgreSQL、Redis、relation-stub を起動します。起動済みの場合は runn のコマンドだけで再実行できます。IdP の起動待ちは health が成功するまで60回、2秒間隔で試行します。各リクエストの timeout は2秒なので、到達できない場合も有限時間で失敗します。ログインやトークン発行は再試行しません。

`runn` コンテナは `scenario/` を `/books` に読み取り専用でマウントし、直下の `*.yml` を実行します。`helpers/` は include 専用です。

## PostgreSQL でのデバイス認可回帰テスト

デバイス認可の Refresh は `edge_device_id` 単位の行ロックと PostgreSQL の `ON CONFLICT` に依存します。既定の Kotlin テストは H2 で動くため、同じテストクラスを PostgreSQL の Testcontainers でも実行します。

`DeviceAuthorizationPostgresFlowTests` は `postgres:17-alpine` を起動し、次を H2 と同じシナリオで検証します。

- 同じ Refresh Token の同時更新は 1 回だけ成功し、もう一方は `invalid_grant` になり、デバイス認可が失効する
- Refresh と revoke の競合後、revoke 済みの端末で更新が成功し続けない
- 一時失効と永久失効、`reapproval=true` による明示的な再承認
- Refresh の永続化失敗時にデバイス認可と古い Token が失効する
- `idp_device_grant_lock` の行が 1 つに保たれる

Docker が使える環境では `./gradlew test` に含まれます。クラスだけを実行する場合は次のとおりです。

```bash
./gradlew test --tests 'dev.usbharu.toloidp.security.DeviceAuthorizationPostgresFlowTests'
```

Docker がない環境ではこのクラスはスキップされます。Colima など Docker の socket が `/var/run/docker.sock` 以外にある場合は、Testcontainers に socket を指定します。

```bash
DOCKER_HOST=unix://$HOME/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
./gradlew test --tests 'dev.usbharu.toloidp.security.DeviceAuthorizationPostgresFlowTests'
```

CI は JVM／Native のビルドで `./gradlew build` を実行したあと、PostgreSQL のテスト結果が存在し、スキップされていないことを確認します。

## 接続とテストデータ

issuer は `http://localhost:18080` です。コンテナ内では `localhost` が runn 自身を指すため、`--host-rules "localhost app:8080"` で接続先を変更します。HTTP の Host ヘッダと Discovery の URL は issuer の値を維持します。

ログイン API は Web のログイン画面（`http://localhost:3000/login`）から呼ぶ形で、`Origin` と `Referer` を付けます。RP の callback は seed client に登録済みの `http://127.0.0.1:8080/login/oauth2/code/client-123` を使用します。302 は追従しないため、callback サーバーは不要です。

seed user `user-123`（`src/main/resources/seed/users.json`）、client `client-123`、Introspection 用の client `service-gateway` と `relation-stub/sample.json` を使用します。seed の認証情報や client policy を変更した既存 DB では、シナリオの前提と一致させてください。テストのために既存 volume を削除する必要はありません。

ホストに同じバージョンの runn がある場合は、起動済みアプリに直接実行できます。

```bash
IDP_ISSUER=http://localhost:18080 runn run --verbose 'scenario/*.yml'
```

## 検証内容

`oidc-login.yml` は次のフローを検証します。

1. Health と Discovery の issuer、endpoint、対応フローを確認する。
2. `0123456789abcdef` の resource、PKCE S256、nonce、state と `openid tenant.read events.read events.manage events.operate events.report` を指定した認可要求が、Web のログイン画面へ `challenge` だけを付けた302を返すことを確認する。
3. `challenge` と資格情報で `/api/login` を呼び、`0123456789abcdef` のログインと HttpOnly のセッション cookie を確認する。
4. `challenge` だけを付けた認可要求で元の要求を再開し、認可コード付きの302を確認する。
5. client の Basic 認証と code verifier でコードを交換し、JWT access token と ID Token の発行を確認する。
6. `service-gateway` の認証付き Introspection で tenant_access の claim を確認する。`client-123` の Introspection は `invalid_client` になることを確認する。
7. `backend-api` 向けの event-1 の `event_access` に交換し、JWT 形式と Introspection の claim を確認する。
8. staff の event-2 への設計・構成の書き込み（`events.manage`）は発行され、未所属の event-3 は `invalid_grant`、許可外 audience は `invalid_target` になることを確認する。
9. Refresh Token による更新、ローテーション、旧 token の再利用拒否、新 token での再更新と scope 縮小を確認する。
10. Refresh Token を revoke し、更新が `invalid_grant`、現在の Access Token の Introspection が `active: false` になることを確認する。
11. 終了時に、発行された最新の ID Token を `id_token_hint` にして Discovery の `end_session_endpoint` を呼び、登録済みの `post_logout_redirect_uri` へ `state` 付きでリダイレクトされることを確認する。ID Token が発行されていれば、後続の検証が失敗してもログアウトを試行する。

`signup-registration.yml` は次のフローを検証します。ユーザー名は実行ごとに変えるので、同じ DB で繰り返し実行できます。

1. Discovery の `scopes_supported` が `tenant.join` を含み、`tenant.claim` を含まないことを確認する。
2. `openid tenant.join` の認可要求が、challenge を発行せずに `invalid_scope` を返すことを確認する。
3. tenant-onboarding の resource と `tenant.join` だけの認可要求が、Web のログイン画面へ `challenge` だけを付けた302を返すことを確認する。
4. `challenge` と新しいユーザー名・パスワードで `/api/signup` を呼び、tenant-onboarding のユーザーと HttpOnly のセッション cookie が作られることを確認する。
5. 認可要求を再開し、コードを registration に交換する。ID Token と Refresh Token がなく、scope が `tenant.join` だけであることを確認する。
6. JWT 本体と Introspection で `token_use=registration` を確認し、`tenant_id`、`event_id`、`resource` がないことを確認する。
7. registration を交換元にした Token Exchange が `invalid_grant` になることを確認する。

scope は順序によらず完全一致を確認します。両 access token の issuer、subject、client、単一 audience、resource、tenant/event、token_use、時刻、jti を確認します。jti は JWT 本体と Introspection の両方で、存在する非空の文字列であることを確認します。role、tenant_role、event_role の不在は JWT 本体をデコードして確認します。Introspection は保存された claim の検証です。JWT 署名検証は既存の Kotlin テストで行います。ID Token の nonce や署名はこの runbook の検証対象に含めません。

password、client secret、login challenge、認可コード、token、セッション cookie は runn の `secrets` に登録しています。runn v1.10.0 の失敗 trace にはマスクされない値が出るため、公開済み seed 値を使う専用開発環境で実行してください。標準の実行は HTTP 詳細を無効にし、ステップの成否と失敗時の trace を表示します。

## CI

GitHub Actions の `Scenario tests` は PR、main 更新、手動実行で動きます。JVM／Native と amd64／arm64 の4通りで Gradle build と同じ runbook を実行します。JVM は Dockerfile から、Native は `bootBuildImage` からイメージを作成し、`TOLO_IDP_IMAGE` で Compose に渡します。

両 runtime のイメージは `docker-compose.production.yaml` の別プロジェクトでも起動し、`production/startup.yml` で Health と Discovery の issuer を検証します。新規 DB と一時署名鍵を用意し、seed は無効のまま実行します。終了時は CI 専用 volume と署名鍵を削除します。本番 Compose には任意の `scenario` profile として runn が含まれています。

token の scope の検証失敗時と token 発行後の検証失敗時に、セッション cookie と ID Token を送ってログアウトすることも合成 HTTP レスポンスで検証します。ID Token が発行される前に失敗した場合は、ログアウトを呼ばないことを確認します。end_session endpoint は `id_token_hint` を必須とするためです。このときのセッションはタイムアウトで破棄されます。runn の失敗はジョブの失敗になります。

CI は実行 ID・runtime・architecture ごとの Compose project を使います。各 runtime のシナリオ成功後には、別の DB と使い捨ての署名鍵を使って本番プロファイルの Health と Discovery も確認します。成功・失敗を問わず、CI のコンテナと volume を終了時に削除します。ローカルの開発用 volume は対象外です。

バージョンタグのリリース CI も同じ再利用ワークフローを呼びます。イメージのビルドと公開については [CI とリリース手順](../CI.md) を参照してください。

失敗時のログアウトだけを確認する場合は、Docker と Python 3 を使って `python3 scenario/tests/test_runn_cleanup.py` を実行します。アプリの起動は不要です。

ブラウザ画面と別オリジンの CORS はこのシナリオの対象外です。ログイン画面へのリダイレクトは `Location` だけを確認し、ログイン画面は開きません。
