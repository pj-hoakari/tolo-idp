# CI とリリース手順

PR と main 更新では JVM／Native × amd64／arm64 の4通りを検証します。リリース時も同じ検証を行い、全ジョブ成功後に Native イメージを GHCR へ公開します。

## 検証

JVM は `Dockerfile` 内でソースからビルドします。Native は Gradle `bootBuildImage` の成果物を直接使用します。Java／Kotlin のコンパイル対象は24、Native コンパイラは Buildpacks 内の GraalVM 25、CPU 指定は `-march=compatibility` です。

Native のビルド環境には十分なメモリを用意してください。ローカルでは Docker VM の12GiB割り当てを使用し、6GiBではビルドが失敗しました。

各ジョブは専用 Compose project で PostgreSQL・Redis・relation-stub を起動し、Gradle build と OIDC／Token Exchange シナリオを実行します。JVM は `docker-compose.dev-jvm.yaml`、Native は `docker-compose.dev-native.yaml` を使い、`TOLO_IDP_IMAGE` に検証対象イメージを指定します。実行ファイルの形式とコンテナの実プロセスも確認します。

Native は同じイメージを `docker-compose.production.yaml` でも起動し、新規 DB と一時署名鍵を使って `scenario/production/startup.yml` の Health と Discovery を確認します。seed は無効です。終了時は成功・失敗にかかわらず CI 専用コンテナ・volume・鍵を削除します。

## リリース

リリース番号の正本は `vMAJOR.MINOR.PATCH` の Git タグです。プレリリースは `v1.2.3-rc.1` のように指定します。日付採番と `+build` metadata は使いません。

```bash
git tag v1.2.3
git push origin v1.2.3
```

`pj-hoakari/actions/resolve-version` がタグ形式、実行コミットとの一致、最新バージョンであることを確認します。解決したバージョンを Gradle の `releaseVersion` と公開タグの両方に渡し、公開前にも再検証します。Action は `d619552a3e89628f83a45f57ac80e9e9c9590859` に固定しています。

手動再実行では GitHub Actions の `Build and publish container image` で対象タグを選択してください。ブランチを選んだ実行はバージョン解決で失敗します。

検証済み Native イメージを architecture ごとの artifact に保存し、公開ジョブで読み込みます。同じ GHCR package に実行 ID・architecture 付きの一時タグで push し、その digest から multi-arch manifest を直接作ります。Dockerfile によるラップや再ビルド、別の Buildpacks package への公開は行いません。artifact は1日で削除します。

| 項目 | 内容 |
|---|---|
| イメージ名 | `ghcr.io/<owner>/tolo-idp` |
| 対応プラットフォーム | `linux/amd64`・`linux/arm64` |
| バージョンタグ | `1.2.3`・`1.2.3-rc.1` |
| コミットタグ | `sha-abcdef0`（先頭7文字） |
| 安定版タグ | `latest`（プレリリースでは更新しない） |

JVM イメージは開発・CI 検証用です。今後の JVM リリースは公開しません。既に公開済みのイメージは削除しません。main 更新でもイメージは公開しません。

ローカルの起動・ビルド方法と本番の必須環境変数は [README.md](README.md) を参照してください。Native のバージョン指定は `./gradlew bootBuildImage -PreleaseVersion=1.2.3`、本番のイメージ指定は `TOLO_IDP_IMAGE=ghcr.io/<owner>/tolo-idp:1.2.3` です。
