# tolo-idp

マルチテナント環境向け OAuth2 / OpenID Connect Authorization Server。仕様は [spec.md](spec.md) を参照してください。

## 起動環境

Spring 設定は `src/main/resources/application.yaml` に集約しています。通常の起動では次の3環境を使います。

| 環境 | Compose | アプリのビルド・実行 |
|---|---|---|
| dev-jvm | `docker-compose.dev-jvm.yaml` | Docker 内でソースから JAR をビルドし、Java 24 で実行 |
| dev-native | `docker-compose.dev-native.yaml` | Gradle Buildpacks で Native イメージを作成して実行 |
| production | `docker-compose.production.yaml` | 検証済みの Native または JVM イメージを実行 |

開発環境は平文の HTTP で動かすため、IdP のログイン状態の cookie を `tolo_idp_session` という名前で、`Secure` を付けずに発行します。本番の cookie 名は `__Host-tolo_idp_session` です。

開発環境には PostgreSQL・Redis・relation-stub が含まれます。IdP は `http://localhost:18080`、PostgreSQL は `localhost:15432`、Redis は `localhost:16379`、relation-stub は `http://localhost:18081` で利用できます。seed user は `user-123` / `password`、client は `client-123` / `secret` です。

### dev-jvm

Docker と Docker Compose が必要です。ホストの Java や Gradle の事前実行は不要です。

```bash
docker compose -f docker-compose.dev-jvm.yaml up -d --build
```

Dockerfile だけでもビルドできます。ホストの `build/` はビルドコンテキストに含めません。

```bash
docker build -t tolo-idp-dev-jvm:local .
```

### dev-native

Docker と Java 24 が必要です。Native コンパイラは Buildpacks 内の GraalVM 25 を使うため、ホストへの GraalVM のインストールは不要です。

```bash
./gradlew bootBuildImage
docker compose -f docker-compose.dev-native.yaml up -d --wait db redis relation-stub
docker compose -f docker-compose.dev-native.yaml up -d app
```

既定のイメージ名は `tolo-idp:0.0.1-SNAPSHOT` です。ソース変更後は `bootBuildImage` を再実行して app を起動し直してください。Compose は Native イメージをビルド・pull せず、ローカルに存在しなければ失敗します。

Native ビルドは多くのメモリを使います。Docker VM の6GiB割り当てでは、メモリ不足になることを確認しています。12GiB以上を目安に割り当ててください。ビルドが失敗する場合は Docker のメモリ割り当てを増やしてください。コンパイラのヒープと並列数は追加引数で指定できます（ヒープ以外にもメモリが必要です）。

```bash
./gradlew bootBuildImage '-PnativeImageExtraBuildArguments=-J-Xmx8g --parallelism=2'
```

AOT は `production` プロファイルで実行し、ビルド中の DB 接続は不要です。`production` / `dev-jvm` / `dev-native` では PostgreSQL の `JdbcDialect` Bean を明示し、AOT 中の方言取得に伴う DataSource 初期化を防いでいます。JDBC Repository のクエリ事前生成は有効なままです。実行時は PostgreSQL を使用します。

ビルドした同じ Native イメージを `dev-native` と `production` の両方で使用できます。AOT はビルド時の `production` プロファイルを起動時にも追加するため、YAML は共通 → 本番 → 開発の順に定義し、明示した開発設定を優先させています。

### production

Native は `ghcr.io/pj-hoakari/tolo-idp`、JVM は `ghcr.io/pj-hoakari/tolo-idp-jvm` に公開します。既定は Native で、`TOLO_IDP_IMAGE` に JVM イメージを指定すると同じ本番 Compose で JVM 版を起動できます。次の環境変数を設定してください。

| 環境変数 | 内容 |
|---|---|
| `TOLO_IDP_IMAGE` | 使用するイメージ。例: `ghcr.io/pj-hoakari/tolo-idp:1.2.3` または `ghcr.io/pj-hoakari/tolo-idp-jvm:1.2.3` |
| `TOLO_IDP_POSTGRES_PASSWORD` | PostgreSQL パスワード。必須 |
| `TOLO_IDP_POSTGRES_USER` | PostgreSQL ユーザー。既定値 `tolo_idp` |
| `TOLO_IDP_ISSUER` | 外部に公開する issuer URL。必須 |
| `TOLO_IDP_LOGIN_PAGE_URL` | Web のログイン画面の URL。例: `https://example.com/login`。必須 |
| `TOLO_IDP_LOGIN_ERROR_PAGE_URL` | Web の認可エラー画面の URL。例: `https://example.com/auth/error`。必須 |
| `SERVER_TOMCAT_REMOTEIP_INTERNALPROXIES` | `X-Forwarded-For` と `X-Forwarded-Proto` を信頼する前段の ingress のアドレス（CIDR）。未設定ならプライベートアドレス帯をすべて信頼するので、本番では ingress のアドレスに絞る |
| `TOLO_IDP_JWK_PRIVATE_KEY_HOST_PATH` | ホスト側の RSA 秘密鍵ファイルの絶対パス。必須 |
| `TOLO_IDP_JWK_PRIVATE_KEY_LOCATION` | コンテナ内の秘密鍵ファイルの絶対パス。例: `/run/tolo-idp/private.pem`。必須 |

秘密鍵は PKCS#8 PEM 形式で、コンテナの非 root ユーザーが読めるファイルを用意します。ファイルは読み取り専用でマウントされます。

```bash
docker compose -f docker-compose.production.yaml up -d
```

IdP の公開ポートは8080です。seed と一時署名鍵は無効です。本番の relation service（tolo-tenant-management）の接続先など、環境固有の設定は Compose の app に環境変数を追加してください（例: `TOLO_IDP_RELATION_BASE_URL`）。

## シナリオの実行・停止

開発環境の起動後、使用中の Compose でシナリオを実行します。

```bash
docker compose -f docker-compose.dev-jvm.yaml --profile scenario run --rm --no-deps runn
# Native の場合は docker-compose.dev-native.yaml を指定する。
```

本番 Compose の同じコマンドは Health と Discovery を確認する startup シナリオを実行します。詳しくは [シナリオ手順](scenario/README.md) を参照してください。

開発環境を切り替える前に、使用中のスタックを停止します。両開発環境はプロジェクト名・ポート・既存の開発用 volume を共有します。

```bash
docker compose -f docker-compose.dev-jvm.yaml down
# または docker compose -f docker-compose.dev-native.yaml down
```

`down` に `--volumes` を付けなければ DB と Redis のデータは保持されます。本番は `docker compose -f docker-compose.production.yaml down` で停止します。旧 local 環境の volume は自動移行・削除しません。

## ビルドとテスト

```bash
./gradlew test
./gradlew build
```

コンパイル対象は Java 24 です。`-PimageRuntime=jvm` は JVM 用ビルドで Native プラグインを適用しないための指定で、Dockerfile 内でも使用します。`bootBuildImage` は Native 専用です。

CI と公開手順は [CI.md](CI.md) を参照してください。

ユーザーは `(tenantId, username)` ごとに管理し、別テナントの同名ユーザーを登録できます。UUID は内部主キーと JWT の `sub` に使い、Relation Service には `(tenantId, username)` を渡します。開発用 seed は `(tenant-a, user-123)`、内部主キーは `71c68dc1-2c72-45ac-a191-1c47c1551011` です。V6 は tenant 情報のない旧ユーザーテーブルを作り直し、開発用ユーザーを seed で再作成します。

認可要求には `resource` に tenant resource（例: `https://api.example.com/tenants/tenant-a`）を指定します。ログイン状態がない要求と `prompt=login` の要求は、Web のログイン画面（開発環境では `http://localhost:3000/login`）へ `challenge` を付けてリダイレクトします。ログイン画面は `POST /api/login` に `username`、`password`、`challenge` を送り、成功したら `/oauth2/authorize?challenge=...` を開いて元の認可要求を再開します。詳しくは [spec.md](spec.md) の 4.1 節と 4.1.3 節を参照してください。

ログイン名の取得には、認可時に `openid profile` scope を要求し、その access token で `GET /userinfo` を呼び出してください。`preferred_username` に現在のログイン名、`sub` に UUID の user ID を返します。
