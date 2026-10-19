# tolo-idp

マルチテナント環境向け OAuth2 / OpenID Connect Authorization Server。仕様は [spec.md](spec.md) を参照してください。

## 起動環境

Spring 設定は `src/main/resources/application.yaml` に集約しています。通常の起動では次の3環境を使います。

| 環境 | Compose | アプリのビルド・実行 |
|---|---|---|
| dev-jvm | `docker-compose.dev-jvm.yaml` | Docker 内でソースから JAR をビルドし、Java 24 で実行 |
| dev-native | `docker-compose.dev-native.yaml` | Gradle Buildpacks で Native イメージを作成して実行 |
| production | `docker-compose.production.yaml` | 検証済みの Native イメージを実行 |

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
# AOT 処理が参照する PostgreSQL を先に起動する。
docker compose -f docker-compose.dev-native.yaml up -d --wait db redis relation-stub
./gradlew bootBuildImage
docker compose -f docker-compose.dev-native.yaml up -d app
```

既定のイメージ名は `tolo-idp:0.0.1-SNAPSHOT` です。ソース変更後は `bootBuildImage` を再実行して app を起動し直してください。Compose は Native イメージをビルド・pull せず、ローカルに存在しなければ失敗します。

Native ビルドは多くのメモリを使います。Docker VM の6GiB割り当てでは、メモリ不足になることを確認しています。12GiB以上を目安に割り当ててください。ビルドが失敗する場合は Docker のメモリ割り当てを増やしてください。コンパイラのヒープと並列数は追加引数で指定できます（ヒープ以外にもメモリが必要です）。

```bash
./gradlew bootBuildImage '-PnativeImageExtraBuildArguments=-J-Xmx8g --parallelism=2'
```

AOT は `production` プロファイルと PostgreSQL を使います。接続先の既定値は `jdbc:postgresql://localhost:15432/tolo_idp`、ユーザーとパスワードは `tolo_idp` です。変更する場合は `-PaotDatasourceUrl=...`・`-PaotDatasourceUsername=...`・`-PaotDatasourcePassword=...` を指定します。ビルドした同じ Native イメージを `dev-native` と `production` の両方で使用できます。AOT はビルド時の `production` プロファイルを起動時にも追加するため、YAML は共通 → 本番 → 開発の順に定義し、明示した開発設定を優先させています。

### production

公開されるイメージは Native のみです。次の環境変数を設定してください。

| 環境変数 | 内容 |
|---|---|
| `TOLO_IDP_IMAGE` | 使用する Native イメージ。例: `ghcr.io/pj-hoakari/tolo-idp:1.2.3` |
| `TOLO_IDP_POSTGRES_PASSWORD` | PostgreSQL パスワード。必須 |
| `TOLO_IDP_POSTGRES_USER` | PostgreSQL ユーザー。既定値 `tolo_idp` |
| `TOLO_IDP_ISSUER` | 外部に公開する issuer URL。必須 |
| `TOLO_IDP_JWK_PRIVATE_KEY_HOST_PATH` | ホスト側の RSA 秘密鍵ファイルの絶対パス。必須 |
| `TOLO_IDP_JWK_PRIVATE_KEY_LOCATION` | コンテナ内の秘密鍵ファイルの絶対パス。例: `/run/tolo-idp/private.pem`。必須 |

秘密鍵は PKCS#8 PEM 形式で、コンテナの非 root ユーザーが読めるファイルを用意します。ファイルは読み取り専用でマウントされます。

```bash
docker compose -f docker-compose.production.yaml up -d
```

IdP の公開ポートは8080です。seed と一時署名鍵は無効です。本番 relation service の接続先など、環境固有の設定は Compose の app に環境変数を追加してください（例: `TOLO_IDP_RELATION_BASE_URL`）。

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
