# シナリオテスト (runn)

[PR #9](https://github.com/pj-hoakari/tolo-idp/pull/9) の OIDC シナリオを、現在の開発環境と Token Exchange に対応させたものです。
[runn v1.10.0](https://github.com/k1LoW/runn/tree/v1.10.0) を Compose の `scenario` profile で実行します。

## 実行方法

リポジトリのルートで実行します。Docker と Compose が必要です。

```bash
docker compose -f docker-compose.dev.native.yaml up -d --build
docker compose -f docker-compose.dev.native.yaml --profile scenario run --rm runn
```

ファイル名は `dev.native` ですが、現在の Compose は `Dockerfile.jvm` で Java 24 の JVM アプリをビルドします。ホストへの Java、GraalVM、runn のインストールや `bootBuildImage` の実行は不要です。

最初のコマンドで IdP、PostgreSQL、Redis、relation-stub を起動します。起動済みの場合は2番目のコマンドだけで再実行できます。IdP の起動待ちは health が成功するまで60回、2秒間隔で試行します。各リクエストの timeout は2秒なので、到達できない場合も有限時間で失敗します。ログインやトークン発行は再試行しません。

`runn` コンテナは `scenario/` を `/books` に読み取り専用でマウントし、直下の `*.yml` を実行します。`helpers/` は include 専用です。

## 接続とテストデータ

issuer は `http://localhost:18080` です。コンテナ内では `localhost` が runn 自身を指すため、`--host-rules "localhost app:8080"` で接続先を変更します。HTTP の Host ヘッダと Discovery の URL は issuer の値を維持します。

ログイン API は IdP と同一オリジンから呼ぶ前提です。RP の callback は seed client に登録済みの `http://127.0.0.1:8080/login/oauth2/code/client-123` を使用します。302 は追従しないため、callback サーバーは不要です。

seed user `user-123`、client `client-123` と `relation-stub/sample.json` を使用します。seed の認証情報や client policy を変更した既存 DB では、シナリオの前提と一致させてください。テストのために既存 volume を削除する必要はありません。

ホストに同じバージョンの runn がある場合は、起動済みアプリに直接実行できます。

```bash
IDP_ISSUER=http://localhost:18080 runn run --verbose 'scenario/*.yml'
```

## 検証内容

`oidc-login.yml` は次のフローを検証します。

1. Health と Discovery の issuer、endpoint、対応フローを確認する。
2. `/api/login` で tenant-a を選択し、HttpOnly のセッション cookie を保持する。
3. PKCE S256、nonce、state と `openid tenant.read events.read events.write` を指定し、認可コード付きの302を確認する。
4. client の Basic 認証と code verifier でコードを交換し、JWT access token と ID Token の発行を確認する。
5. 認証付き Introspection で tenant_access の claim を確認する。
6. `backend-api` 向けの event-1 の `event_access` に交換し、JWT 形式と Introspection の claim を確認する。
7. event-2 への write は `invalid_scope`、未所属の event-3 は `invalid_grant`、許可外 audience は `invalid_target` になることを確認する。
8. 終了時にセッションを破棄する。ログイン後のステップが失敗した場合も logout を試行する。

scope は順序によらず完全一致を確認します。両 access token の issuer、subject、client、単一 audience、resource、tenant/event、token_use、時刻、jti を確認します。jti は JWT 本体と Introspection の両方で、存在する非空の文字列であることを確認します。role、tenant_role、event_role の不在は JWT 本体をデコードして確認します。Introspection は保存された claim の検証です。JWT 署名検証は既存の Kotlin テストで行います。ID Token の nonce や署名はこの runbook の検証対象に含めません。

password、client secret、認可コード、token、セッション cookie は runn の `secrets` でマスクします。標準の実行はステップの成否だけを表示し、HTTP 詳細を出力しません。トークンや cookie の dump を追加しないでください。

## CI

GitHub Actions の `Scenario tests` は PR、main 更新、手動実行で動きます。Java 24 で `./gradlew build` を実行し、同じ Compose と runbook でシナリオを検証します。runn の失敗はジョブの失敗になります。

CI は run ごとの Compose project を使います。成功・失敗を問わず、その project のコンテナと volume を終了時に削除します。ローカルの開発用 volume は対象外です。

ブラウザ画面、未ログイン時の画面遷移、別オリジンの CORS、Native Image はこのシナリオの対象外です。
