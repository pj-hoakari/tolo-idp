# Better Auth から tolo-idp を試す

Next.js と Better Auth 1.7.4 のローカル検証アプリです。OIDC ログイン、Token Exchange、Refresh Token の更新・ローテーション・明示的な失効を試せます。

## 起動

Node.js 24 と Docker を使用します。リポジトリのルートで IdP を起動します。

```bash
docker compose -f docker-compose.dev.native.yaml up -d --build
```

別ターミナルで検証アプリを起動します。

```bash
cd local/better-auth-test
cp .env.local.example .env.local # 初回のみ。既存の設定は上書きしない
npm ci
npm run db:migrate
npm run dev
```

[検証画面](http://localhost:3000) を開きます。IdP は `http://localhost:18080`、Better Auth の callback は `http://localhost:3000/api/auth/callback/tolo-idp` です。callback は開発用 `client-123` に登録済みです。

`.env.local.example` の認証情報はローカル開発専用です。`.env.local` と `sqlite.db` は Git 管理対象外です。`bootRun` などで IdP のポートを変える場合は `.env.local` の `TOLO_IDP_URL` と `NEXT_PUBLIC_TOLO_IDP_URL` を同じ URL に変更します。

## 試す手順

1. `user-123` / `password` / `tenant-a` で **1. Login to IdP** を押します。
2. **2. Continue with OIDC** を押します。Better Auth が Authorization Code + PKCE、ID Token の署名・issuer・audience・nonce の検証を行い、dashboard に進みます。
3. **3. Exchange for event_access** を押します。`event-1` / `events.read` / `backend-api` で `event_access` を確認できます。`event-3` は未所属のため拒否されます。
4. **4. Refresh Token で更新** を押します。`refreshTokenRotated: true`、`refreshTokenSaved: true`、`idTokenIssued: true` と新しい `jti` を確認します。更新には Better Auth の標準 `auth.api.refreshToken` を使用し、ローテーション後の token を Better Auth が保存します。
5. **IdP セッションを終了** の後、もう一度 Refresh を押します。Better Auth のセッションと Refresh Token は残っているため更新できます。
6. **5. Refresh Token を revoke** を押します。`revoked: true`、`accessTokenActive: false` を確認します。
7. もう一度 Refresh を押します。`FAILED_TO_REFRESH_ACCESS_TOKEN` で拒否されれば失効が効いています。
8. やり直すときは **Better Auth からサインアウトしてログインし直す** を押します。

Better Auth のサインアウト、IdP セッション終了、Refresh Token の revoke は画面で別々に試せます。自動的な連動は行いません。revoke 後の更新拒否を試すため、失効済み token は検証アプリの保存データに残します。

Refresh Token と client secret はサーバー側だけで使用します。画面には token の存在、ローテーション・保存の結果と JWT claim を表示し、Refresh Token 本体は返しません。業務 scope を追加したい場合は `src/lib/auth.ts` の登録を変更し、OIDC ログインをやり直します。`offline_access` は IdP で未対応のため要求しません。

## 確認

アプリを起動した状態で実行します。

```bash
npm run typecheck
npm test
```

テストは未ログインの token 操作が `401`、異なる Origin・Origin 省略が `403`、不正な操作が `400` になることを確認します。正常なログイン・更新・revoke は上記の画面手順で確認します。
