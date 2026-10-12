# CI とリリース手順

PR と main 更新では JVM／Native × amd64／arm64 の4通りを検証します。リリース時も同じ検証を行い、全ジョブ成功後に GHCR へ公開します。

## バージョンタグを push してリリースする

リリース番号の正本は `vMAJOR.MINOR.PATCH` の Git タグです。プレリリースは `v1.2.3-rc.1` のように指定します。日付採番と `+build` metadata は使いません。

```bash
git tag v1.2.3
git push origin v1.2.3
```

`pj-hoakari/actions/resolve-version` がタグ形式、実行コミットとの一致、最新バージョンであることを確認します。解決した `1.2.3` を Gradle の `releaseVersion` と公開タグの両方に渡します。ビルド中に新しいタグが追加された場合も、公開前の再検証で古いバージョンの公開を止めます。

手動で再実行する場合は、GitHub Actions の `Build and publish container image` で対象のタグを選択してください。ブランチを選んだ実行はバージョン解決で失敗します。

| 項目 | Native | JVM |
|---|---|---|
| イメージ名 | `ghcr.io/<owner>/tolo-idp` | `ghcr.io/<owner>/tolo-idp-jvm` |
| バージョンタグ | `1.2.3` | `1.2.3` |
| コミットタグ | `sha-abcdef0` | `sha-abcdef0` |
| 安定版タグ | `latest` | `latest` |

Native 版は既存の `tolo-idp` を使い、JVM 版は別のイメージ名 `tolo-idp-jvm` で公開します。各タグに `linux/amd64` と `linux/arm64` が含まれます。プレリリースは latest を更新しません。main 更新ではイメージを公開せず、major.minor タグも作成しません。

## Spring Buildpacks と Dockerfile の両方を使う

再利用ワークフローは Java 24 で Gradle build を実行し、`bootBuildImage` の成果物を `Dockerfile` の `BASE_IMAGE` 引数に渡します。この最終イメージで OIDC／Token Exchange のシナリオを実行します。本番プロファイルは新規 DB と一時署名鍵を使った別の Compose プロジェクトで起動し、`scenario/production/startup.yml` で Health と Discovery の issuer を検証します。

Java／Kotlin のコンパイル対象は24です。Native のビルドには Buildpacks 内の GraalVM 25 を使い、`-march=compatibility` を指定します。JVM 版には Java 24 を使います。最新の Paketo builder は Java 24 を含まないため、JVM 版だけ `builder-noble-java-tiny:0.0.62` の digest に固定しています。Native 版は最新の Noble Java Tiny builder を使います。

公開ジョブは検証済みの Buildpacks イメージを artifact から読み込み、`ghcr.io/<owner>/tolo-idp-buildpacks` に実行 ID 付きのタグで保存します。runtime ごとの manifest を作り、その digest を `ARG BASE_IMAGE` のデフォルト値に設定した `Dockerfile.release` を生成します。それ以外の内容は既存の `Dockerfile` と同じです。中間イメージはこの別 package に保持し、artifact は1日で削除します。

共通 Action は [pj-hoakari/actions の main にあるコミット](https://github.com/pj-hoakari/actions/commit/d619552a3e89628f83a45f57ac80e9e9c9590859) の SHA に固定しています。`publish-image` へ `version`、`image`、`file`、`cache-scope` を渡し、公開先と生成した Dockerfile を指定します。バージョン・コミット・安定版のタグは共通 Action が生成します。両方に同じリリースタグを使い、Actions 側への変更は不要です。

## ローカルで Buildpacks イメージを作る

Java 24 と Docker が必要です。Native の AOT 処理は本番の PostgreSQL 設定に合わせます。

```bash
# JVM
./gradlew bootBuildImage -PimageRuntime=jvm -PreleaseVersion=1.2.3
docker build --build-arg BASE_IMAGE=tolo-idp-jvm:1.2.3 -t tolo-idp-jvm:1.2.3-final .

# Native（imageRuntime を省略した場合も Native）
./gradlew bootBuildImage -PimageRuntime=native -PreleaseVersion=1.2.3
docker build --build-arg BASE_IMAGE=tolo-idp:1.2.3 -t tolo-idp:1.2.3-final .
```

`releaseVersion` を省略すると `0.0.1-SNAPSHOT` を使います。不正な `imageRuntime` はビルド開始時に拒否します。AOT 用の DB 接続値は `aotDatasourceUrl`、`aotDatasourceUsername`、`aotDatasourcePassword` で指定できます。実行時の DB 接続や署名鍵は従来どおり環境変数で指定します。

本番 Compose のイメージは `TOLO_IDP_IMAGE` で選択できます。

```bash
TOLO_IDP_IMAGE=ghcr.io/<owner>/tolo-idp:1.2.3 docker compose -f docker-compose.prod.yaml up -d
```

本番起動には既存の DB パスワード・issuer・署名鍵の環境変数も必要です。シナリオだけをローカルで実行する場合は [scenario/README.md](scenario/README.md) の開発手順を使ってください。
