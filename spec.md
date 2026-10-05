# IdP / Authorization Server Token Exchange 仕様

## 1. 目的

本仕様は、IdP / Authorization Server におけるユーザー認証後の `tenant_access` token 発行、および `tenant_access` token から `event_access` token への OAuth2 Token Exchange を定義する。

本仕様は IdP / Authorization Server の仕様であり、BFF、Browser、フロントエンド、ログイン画面、テナント選択UI、Resource Server の詳細実装は対象外とする。

---

## 2. 適用範囲

### 2.1 扱うもの

```text
- ユーザー認証後の tenant_access token 発行
- tenant_access token の claim
- tenant_access → event_access の Token Exchange
- event_access token の claim
- client 認可
- relation service 参照
- relation service 参照結果の短期キャッシュ
- relation service キャッシュの内部パージ API
- audience 検証
- resource 検証
- scope 検証
- JWT 発行
- JWT 失効方針
- 監査ログ
- エラー方針
```

### 2.2 扱わないもの

```text
- BFF 仕様
- Browser 仕様
- フロントエンド仕様
- ログイン画面
- email 入力後のテナント選択 UI
- Resource Server の詳細実装
```

---

## 3. 前提

Authorization Server は REST API を用いてユーザー認証を行う。

認証成功後、Authorization Server は Spring Security セッションに選択 tenant を保存し、その後の Authorization Code フローで特定 tenant 文脈を持つ `tenant_access` token を JWT access token として発行する。

本仕様では `login` token は定義しない。

本仕様における Token Exchange は、`tenant_access` token を subject token として、`event_access` token を発行する処理のみを対象とする。

---

## 4. ログイン API

### 4.1 ログイン

```http
POST /api/login
Content-Type: application/json

{
  "username": "user-123",
  "password": "password",
  "tenantId": "tenant-a"
}
```

`/api/login` は未認証で呼び出せる。現行実装ではアプリケーション API の CSRF 検証は無効化する。

Authorization Server は以下を確認する。

```text
- tenantId が ID 形式に一致する
- username / password が IdP 内の user と一致する
- relation service 上で user が tenant に所属している
```

成功時は Spring Security セッションを作成し、選択 tenant をセッションに保存する。

レスポンス:

```json
{
  "username": "user-123",
  "tenantId": "tenant-a",
  "resource": "https://api.example.com/tenants/tenant-a",
  "authorities": ["ROLE_USER"]
}
```

認証失敗は `401 Unauthorized`、tenant 不許可は `403 Forbidden` とする。

### 4.2 ログアウト

```http
POST /api/logout
```

認証済みセッションから呼び出す。

セッションを破棄し、`204 No Content` を返す。

---

## 5. token 種別

### 5.1 tenant_access token

`tenant_access` token は、認証済みユーザーに対して発行される、特定 tenant 文脈を持つ JWT access token である。

用途:

```text
- tenant 文脈での API アクセス
- event_access token への Token Exchange の subject_token
```

例:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "backend-api",
  "client_id": "client-123",
  "scope": "tenant.read tenant.write events.read events.manage events.operate events.report",
  "token_use": "tenant_access",
  "resource": "https://api.example.com/tenants/tenant-a",
  "tenant_id": "tenant-a",
  "iat": 1710000000,
  "nbf": 1710000000,
  "exp": 1710000900,
  "jti": "jti-tenant-001"
}
```

### 5.2 event_access token

`event_access` token は、`tenant_access` token から Token Exchange により発行される、特定 event 文脈を持つ JWT access token である。

用途:

```text
- 特定 event 文脈での API アクセス
```

例:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "backend-api",
  "client_id": "client-123",
  "scope": "events.read events.manage events.operate events.report",
  "token_use": "event_access",
  "resource": "https://api.example.com/tenants/tenant-a/events/event-1",
  "tenant_id": "tenant-a",
  "event_id": "event-1",
  "iat": 1710000000,
  "nbf": 1710000000,
  "exp": 1710000600,
  "jti": "jti-event-001"
}
```

---

## 6. Token Exchange 遷移ルール

Authorization Server は以下の Token Exchange のみを許可する。

| 交換元 token_use | 発行先 token_use | 許可 |
|---|---|---|
| `tenant_access` | `event_access` | 許可 |

以下は禁止する。

| 交換元 token_use | 発行先 token_use |
|---|---|
| `tenant_access` | `tenant_access` |
| `event_access` | `tenant_access` |
| `event_access` | `event_access` |

`login` token は本仕様では定義しない。

許可されない遷移が要求された場合、Authorization Server は `invalid_grant` を返す。

---

## 7. audience 仕様

`audience` は Resource Server の論理識別子である。

具体的な audience 名は本仕様では固定しない。

確定ルール:

```text
- Token Exchange Request では audience を必須とする
- audience は Authorization Server への登録制とする
- client ごとに allowed_audiences を持つ
- 1 access token は 1 audience のみを持つ
- 複数 audience を持つ access token は発行しない
```

要求された `audience` が client に許可されていない場合、Authorization Server は `invalid_target` を返す。

---

## 8. client 認可仕様

Authorization Server は `client_id` ごとに以下の設定を持つ。

```text
client_id
client_type
allowed_grant_types
allowed_token_exchange_transitions
allowed_audiences
allowed_scopes
tenant_access_ttl_seconds
event_access_ttl_seconds
```

### 8.1 Token Exchange 許可条件

Authorization Server は Token Exchange Request に対して以下を検証する。

```text
- client が認証済みである
- client が confidential client である
- client に token-exchange grant が許可されている
- requested audience が client.allowed_audiences に含まれる
- requested scope が client.allowed_scopes に含まれる
- requested token_use 遷移が client.allowed_token_exchange_transitions に含まれる
```

### 8.2 禁止事項

```text
- public client からの Token Exchange
- 未登録 client からの Token Exchange
- allowed_audiences 外の audience 要求
- allowed_scopes 外の scope 要求
- 許可されていない token_use 遷移
```

---

## 9. role / scope 仕様

### 9.1 role

Authorization Server が scope 発行可否の判定に使う暫定 role:

```text
owner
admin
staff
```

`owner` / `staff` は relation service から取得する外部 role である。

`admin` は IdP 内部設定または将来の本番 relation service で扱う可能性がある role であり、現時点の `tolo-relation-stub` からは返却されない。

### 9.2 scope

業務スコープは以下の 7 種類とする。

| scope | 意味 | 主な RPC |
|---|---|---|
| `tenant.read` | テナントの参照と、自デバイスに限った書き込み | ListMemberships、RegisterDeviceToken / UnregisterDeviceToken |
| `tenant.write` | テナント構成の書き込み（管理系書き込みの 6 RPC） | ArchiveTenant、ChangeTenantContract、AddTenantMember、ChangeTenantRole、GrantEventRole、RevokeRole |
| `events.read` | イベントの参照 | ListEvents、GetGraph、GetEventOverview、FetchDeliveries、IssueFirestoreToken など |
| `events.manage` | 設計・構成の書き込み | CreateEvent、AssignEventType、TransitionEventStatus、UpdateObservationSettings、SaveGraph、PublishRevision、QR 設置箇所の追加・更新・削除、RegisterEdgeDevice / UnregisterEdgeDevice など |
| `events.operate` | 現場運用の書き込み（11 RPC） | OperateGate、ToggleDangerFlag、ReportCongestion、SendStaffMessage、DirectReassignment など |
| `events.report` | 計測報告と稼働通知 | ReportMeasurements、Heartbeat |
| `tenant.claim` | 仮テナントの所有権取得専用 | ClaimTenantOwnership のみ |

OIDC の `openid` は業務スコープとは別に扱う。tenant_access では role 判定から除外するが、client の登録スコープと `allowed_scopes` に含まれていることを要求する。

旧 `events.write` は廃止する。新しい発行要求では、登録設定に残っていても拒否する。新スコープへの暗黙の変換は行わない。

### 9.3 role → scope 対応表

| role | 許可 scope |
|---|---|
| `owner` | `tenant.read`, `tenant.write`, `events.read`, `events.manage`, `events.operate`, `events.report`, `tenant.claim` |
| `admin` | `tenant.read`, `tenant.write`, `events.read`, `events.manage`, `events.operate`, `events.report`, `tenant.claim` |
| `staff` | `tenant.read`, `events.read`, `events.operate`, `events.report`, `tenant.claim` |

`tenant.claim` の発行先と併用条件は 11.3 に従う。

### 9.4 role の扱い

role は Authorization Server が scope 発行可否を判定するための内部情報である。

role は JWT claim には含めない。

relation service から取得した role は、JWT claim へ転記せず、scope 発行判定の入力としてのみ使う。

---

## 10. relation service 参照仕様

Authorization Server は tenant / event の所属関係、および subject user の role を relation service から取得する。

現時点では `tolo-relation-stub` を暫定 relation service 契約として扱う。

### 10.1 参照 API

Authorization Server は、resource から得た `tenantId` と subject user id を用いて、以下の API を参照する。

```http
GET /tenants/{tenantId}/users/{userId}
```

Token Exchange では `userId` に JWT の `sub` をそのまま使う。ログイン時は認証済み user の username をそのまま使う。

### 10.2 response

relation service は以下の JSON を返す。

```json
{
  "tenant": { "id": "tenant-a", "role": "owner" },
  "user": { "id": "user-123" },
  "events": [
    { "id": "event-1", "role": "staff" }
  ]
}
```

`tenant.role` は、user が対象 tenant に role を持たない場合 `null` である。

`events` は、対象 tenant 配下の event のうち、user が role を持つもののみを含む。該当 event がない場合は空配列である。

relation service が返す外部 role は以下のみとする。

```text
owner
staff
```

### 10.3 relation model 制約

relation service のモデル制約は以下とする。

```text
- 1 user は最大 1 tenant に所属する
- event は必ず 1 tenant に属する
- event role を持つ user は、その event の所属 tenant に tenant role を持つ
- tenant role と event role は独立している
```

例: tenant role が `staff` で event role が `owner` の user は成立する。

### 10.4 relation lookup の扱い

Authorization Server は relation service の結果を以下のように扱う。

```text
- tenant.role == null の場合、subject user は対象 tenant の member ではない
- resource の eventId が events[].id に存在しない場合、subject user は対象 event にアクセスできない
- event_access token の scope 判定には、該当 events[].role を使う
- tenant_access token の scope 判定には、tenant.role を使う
```

relation service が `404` を返した場合、対象 tenant は token 発行対象として扱わない。

relation service への通信失敗、timeout、不正 response、未知 role は、token 発行不可として扱う。

### 10.5 IdP 側の入口制約

`tolo-relation-stub` は ID 値を単純な文字列として扱うが、Authorization Server は本仕様の ID 形式制限を入口で必ず適用する。

Authorization Server は、ID 形式検証に失敗した値を relation service へ問い合わせてはならない。

### 10.6 relation lookup cache

Authorization Server は relation service の成功レスポンスを DB に短期間キャッシュする。

キャッシュキー:

```text
tenant_id
user_id
```

保存内容:

```text
- TenantMembership payload
- cached_at
- expires_at
```

キャッシュ TTL は `tolo-idp.relation.cache.ttl` で設定し、デフォルトは 5 分とする。

キャッシュの扱い:

```text
- expires_at > now の成功レスポンスのみを hit とする
- miss または期限切れの場合は relation service に問い合わせる
- relation service の成功レスポンスのみを保存する
- 404、membership 不足、通信失敗、timeout、不正 response、未知 role はキャッシュしない
- tenantId は ID 形式を検証し、検証失敗時は relation service へ問い合わせない
- tenantId / userId は trim、大文字小文字変換、Unicode 正規化を行わず、そのままキャッシュキーに使う
```

### 10.7 relation cache purge API

relation cache は内部 API でパージできる。

```http
DELETE /internal/relation-cache
```

すべての relation cache entry を削除し、`204 No Content` を返す。

```http
DELETE /internal/relation-cache/tenants/{tenantId}/users/{userId}
```

指定した `(tenantId, userId)` の relation cache entry のみを削除し、`204 No Content` を返す。

`tenantId` は ID 形式を検証する。`userId` は trim、大文字小文字変換、Unicode 正規化を行わず、path value をそのまま削除キーに使う。

この API は server 間通信用の内部 API であり、Spring Security X.509 client certificate authentication で保護する。

認可条件:

```text
- client certificate から抽出された subject/CN が `tolo-idp.relation.cache.admin-subjects` に含まれる
- 許可された subject には `ROLE_RELATION_CACHE_ADMIN` を付与する
- allow-list のデフォルトは空であり、未設定ではパージ API は許可されない
```

CSRF はこの内部 API では無効化する。

X.509 client certificate がない場合は `401 Unauthorized`、allow-list 外の subject/CN の場合は `403 Forbidden` とする。

---

## 11. scope 発行ルール

Authorization Server は、要求された `scope` を暗黙に縮小して発行してはならない。

要求 scope に client / role / token 種別で許可されない scope が含まれる場合、Authorization Server は `invalid_scope` を返す。ただし、Token Exchange の要求 scope が交換元 token の scope を超える場合は、既存の扱いに従い `invalid_grant` を返す。

### 11.1 tenant_access token 発行時

`tenant_access` token 発行時、Authorization Server は以下を満たす scope のみ発行する。

```text
requested_scope ⊆ client.allowed_scopes
requested_scope ⊆ tenant_role.allowed_scopes
```

`tenant_role` は relation service の `tenant.role` から取得する。`tenant.role == null` の場合、tenant_access token は発行しない。

`admin` を使う場合は、IdP 内部設定または将来の本番 relation service の role mapping により `tenant_role` へ割り当てる。`tolo-relation-stub` の response から `admin` を推定してはならない。

### 11.2 event_access token 発行時

`tenant.claim` は発行しない。要求に含まれる場合は `invalid_scope` とする。

既存の共通 role / scope 判定を維持し、`tenant.read` / `tenant.write` も以下の条件を満たせば発行できる。`openid` は event role の許可 scope に含まれず、発行しない。

`event_access` token 発行時、Authorization Server は以下を満たす scope のみ発行する。

```text
requested_scope ⊆ client.allowed_scopes
requested_scope ⊆ subject_token.scope
requested_scope ⊆ event_role.allowed_scopes
```

`event_role` は relation service の `events[].role` から取得する。

resource の `eventId` に一致する event が `events` に存在しない場合、event_access token は発行しない。

`admin` を使う場合は、IdP 内部設定または将来の本番 relation service の role mapping により `event_role` へ割り当てる。`tolo-relation-stub` の response から `admin` を推定してはならない。

### 11.3 tenant.claim token 発行時

`tenant.claim` は所属済みの `owner` / `admin` / `staff` に対して、既存の Authorization Code フローで tenant_access token にのみ発行する。

要求 scope は以下のいずれかに限定する。

```text
tenant.claim
openid tenant.claim
```

他の業務 scope との混在は `invalid_scope` とする。認可リクエスト時と JWT 発行時の両方で検証する。

通常の tenant_access と同じく、認証、選択 tenant の membership、client の許可 scope を検証する。新しい token_use や claim は追加しない。

仮テナントの状態、所有権取得資格、ClaimTenantOwnership の最終認可は Resource Server が確認する。未所属ユーザーへの発行と所有権取得 RPC の実装は本仕様の対象外とする。

tenant.claim のみを持つ token からイベント系 scope への Token Exchange は、交換元 scope を超えるため `invalid_grant` とする。

---

## 12. resource 仕様

### 12.1 採用方針

Token Exchange Request では、対象 event の指定に `resource` パラメータを使用する。

`x_tenant_id` / `x_event_id` は使用しない。

### 12.2 tenant resource

`tenant_access` token の resource は以下の形式とする。

```text
https://api.example.com/tenants/{tenantId}
```

### 12.3 event resource

`event_access` token を要求する場合、Token Exchange Request の `resource` は以下の形式とする。

```text
https://api.example.com/tenants/{tenantId}/events/{eventId}
```

### 12.4 resource 検証

Authorization Server は `resource` について以下を検証する。

```text
- 絶対 URI である
- scheme が https である
- host が許可済みである
- path が許可パターンに一致する
- tenantId / eventId が ID 形式に一致する
- relation service 上で tenant が token 発行対象として扱える
- relation service 上で event が tenant に属している
- relation service 上で subject user が対象 event にアクセス可能である
```

### 12.5 ID 形式

tenantId / eventId は以下の形式に限定する。

```text
^[A-Za-z0-9_-]{1,64}$
```

入力値は以下を行わない。

```text
- trim しない
- 大文字小文字変換しない
- Unicode 正規化しない
```

---

## 13. JWT 仕様

### 13.1 token 形式

Access Token はすべて JWT とする。

```text
- Opaque Token は使用しない
- Resource Server は JWT を自己検証できる
- 認証済み client 向けに Token Introspection を提供する
```

Token Introspection は RFC 7662 の `POST /oauth2/introspect` とする。

Introspection Request は登録済み client の認証を必須とする。confidential client と public client のどちらも Introspection を利用できる。

存在しない token、失効済み token、期限切れ token、nbf より前の token は以下のように返す。

```json
{
  "active": false
}
```

active token の場合、Authorization Server は保存済み JWT claim を元に、少なくとも以下を返す。

```text
active
client_id
scope
aud
iss
sub
exp
iat
nbf
jti
token_use
resource
tenant_id または event_id
```

Introspection Response とログに以下を含めてはならない。

```text
access token 本体
refresh token 本体
client secret
authorization code
password
```

### 13.2 共通必須 claim

```text
iss
sub
aud
client_id
scope
token_use
resource
iat
nbf
exp
jti
```

### 13.3 tenant_access token 必須 claim

```text
tenant_id
```

### 13.4 event_access token 必須 claim

```text
tenant_id
event_id
```

### 13.5 JWT に含めない claim

以下の claim は JWT に含めない。

```text
role
tenant_role
event_role
```

---

## 14. Token Exchange Request

### 14.1 event_access token 発行

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={tenant_access_token}
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=backend-api
&resource=https://api.example.com/tenants/tenant-a/events/event-1
&scope=events.read events.manage events.operate events.report
```

Authorization Server は以下を確認する。

```text
- client が認証済みである
- client が Token Exchange を許可されている
- subject_token が有効である
- subject_token_type が access_token である
- subject_token.token_use == tenant_access
- requested audience が client に許可されている
- requested resource が event resource 形式である
- subject_token.tenant_id == resource の tenantId
- relation service cache または relation service に subject_token.sub と resource の tenantId を問い合わせる
- relation service の tenant.role が null ではない
- resource の eventId が relation service の events[].id に存在する
- requested_scope が subject_token.scope を超えていない
- requested_scope が client / event_role に許可されている
```

---

## 15. event status の扱い

event status に基づく細かい業務判断は Authorization Server の責務ではない。

Authorization Server は、event_access token 発行時に、対象 event が token 発行対象として有効かのみ確認する。

Authorization Server が行ってよい確認:

```text
- relation service 上で event が存在する
- relation service 上で event が tenant に属している
- relation service 上で user が event にアクセス可能である
- event が token 発行自体に不適切な状態ではない
```

Resource Server 側で扱うべき判断:

```text
- draft / open / locked / closed などの業務状態に基づく操作可否
- write 操作が現在可能か
- 参加者追加可能期間か
- イベントが満員か
- その他業務ルール
```

---

## 16. role / permission 変更時の方針

JWT 内の `scope` は発行時点の認可スナップショットである。

Resource Server の主判定は `scope` とする。

role は主に Authorization Server が scope 発行時に使う内部情報である。

### 16.1 write 系 API

`tenant.write`、`events.manage`、`events.operate`、`events.report`、`tenant.claim` を必要とする API、および `tenant.read` による自デバイスへの書き込み API では、Resource Server は DB 上の現在の membership / permission を確認し、token 内の scope が現在も許可可能であることを確認する。

### 16.2 read 系 API

read 系 API は短命 token を基本とする。

ただし、read 権限の即時剥奪が必要な API では、Resource Server は現在の membership / permission を確認する。

---

## 17. 失効方針

JWT のみを使用するため、失効は以下の方針とする。

```text
- access token は短命にする
- すべての JWT に jti を含める
- 強制失効が必要な場合は jti denylist を使う
- jti denylist への登録入口は RFC 7009 Token Revocation endpoint とする
- denylist の TTL は token の exp までとする
```

### 17.1 Token Revocation endpoint

```http
POST /oauth2/revoke
Authorization: Basic ...
Content-Type: application/x-www-form-urlencoded

token=...
token_type_hint=access_token
```

`token_type_hint` は未指定、または `access_token` のみ許可する。
`refresh_token` など access token 以外の hint は `unsupported_token_type` を返す。

Revocation 対象は `tenant_access` / `event_access` の JWT access token のみとする。

Authorization Server は以下を確認する。

```text
- client が認証済みである
- client が confidential client である
- token が access token として保存されている場合、発行先 client と revocation 要求 client が一致する
- token の JWT claim に jti / exp / token_use が存在する
```

有効な対象 token の revocation では、Authorization Server は token の `jti` を
`idp_jti_denylist` に登録し、`expires_at` には token の `exp` を設定する。
`exp` が現在時刻以前の場合は denylist へ登録しない。

Revocation は RFC 7009 に従い、以下は `200 OK` の空レスポンスとする。

```text
- revocation 成功
- 未知 token
- 期限切れ token
- 既に失効済みの token
```

別 client が発行した token の revocation、client 認証不正、public client からの
revocation、access token 以外の hint は OAuth2 error とする。

Revocation endpoint は token 本体、client secret、authorization code、password を
レスポンスおよびログへ出力してはならない。

### 17.2 token TTL

現行実装のデフォルト TTL:

| token_use | TTL |
|---|---|
| `tenant_access` | 15分 |
| `event_access` | 10分 |

client policy の `tenant_access_ttl_seconds` / `event_access_ttl_seconds` により client ごとに設定する。

---

## 18. エラー方針

外部レスポンスでは、tenant / event / membership の詳細を漏らさない。

### 18.1 Token Exchange が許可されない場合

```json
{
  "error": "invalid_grant",
  "error_description": "The token exchange request is not allowed"
}
```

以下は外部上は同じエラーにまとめる。

```text
tenant_not_found
event_not_found
event_not_in_tenant
user_not_tenant_member
user_not_event_member
relation_lookup_failed
relation_response_invalid
relation_role_unknown
invalid_token_use_transition
token_revoked
```

relation service の `404 tenant not found`、通信失敗、timeout、不正 response、未知 role、membership 不足は、外部レスポンスで詳細を区別しない。

現行実装では Spring Authorization Server の `OAuth2Error` として error code を返す。`error_description` の具体的な文言は固定しない。

### 18.2 scope が許可されない場合

```json
{
  "error": "invalid_scope",
  "error_description": "The requested scope is not allowed"
}
```

### 18.3 audience / resource が許可されない場合

```json
{
  "error": "invalid_target",
  "error_description": "The requested target is not allowed"
}
```

### 18.4 リクエスト形式が不正な場合

```json
{
  "error": "invalid_request",
  "error_description": "The token exchange request is invalid"
}
```

---

## 19. 監査ログ仕様

Token Exchange と Token Revocation は認可境界であるため、成功・失敗の両方を必ず監査ログに記録する。

### 19.1 記録項目

```text
timestamp
request_id
client_id
subject
source_token_use
requested_token_use
requested_audience
requested_resource
requested_scope
issued_scope
tenant_id
event_id
result
failure_reason
source_ip
user_agent
issued_jti
```

現行実装では Token Exchange の監査ログを DB の `idp_audit_log` と logger `audit.token` に記録する。
Token Revocation も同じ `idp_audit_log` と logger `audit.token` に記録する。
Revocation の場合、`requested_token_use` は `revocation`、`issued_jti` は失効対象の
`jti` とする。

`request_id`、`source_ip`、`user_agent` は項目として保持するが、現行実装では request からの自動設定は行わない。

### 19.2 ログに出してはいけないもの

```text
access token 本体
refresh token 本体
client_secret
authorization code
password
```

### 19.3 result

```text
success
failure
```

### 19.4 failure_reason 例

```text
invalid_token_use_transition
client_not_allowed
audience_not_allowed
resource_invalid_format
resource_not_allowed
tenant_not_found
event_not_found
event_not_in_tenant
user_not_tenant_member
user_not_event_member
relation_lookup_failed
relation_response_invalid
relation_role_unknown
scope_not_allowed_for_client
scope_not_allowed_for_role
scope_not_allowed_for_token_use
scope_exceeds_subject_token
token_revoked
unsupported_token_type
token_invalid_claims
```

### 19.5 成功ログ例

```json
{
  "timestamp": "2026-05-20T10:00:00Z",
  "request_id": "req-abc",
  "client_id": "client-123",
  "subject": "user-123",
  "source_token_use": "tenant_access",
  "requested_token_use": "event_access",
  "requested_audience": "backend-api",
  "requested_resource": "https://api.example.com/tenants/tenant-a/events/event-1",
  "requested_scope": ["events.read", "events.manage", "events.operate", "events.report"],
  "issued_scope": ["events.read", "events.manage", "events.operate", "events.report"],
  "tenant_id": "tenant-a",
  "event_id": "event-1",
  "result": "success",
  "failure_reason": null,
  "source_ip": "203.0.113.10",
  "user_agent": "Mozilla/5.0 ...",
  "issued_jti": "jti-event-001"
}
```

### 19.6 失敗ログ例

```json
{
  "timestamp": "2026-05-20T10:00:00Z",
  "request_id": "req-def",
  "client_id": "client-123",
  "subject": "user-123",
  "source_token_use": "tenant_access",
  "requested_token_use": "event_access",
  "requested_audience": "backend-api",
  "requested_resource": "https://api.example.com/tenants/tenant-a/events/event-2",
  "requested_scope": ["events.manage"],
  "issued_scope": [],
  "tenant_id": "tenant-a",
  "event_id": "event-2",
  "result": "failure",
  "failure_reason": "user_not_event_member",
  "source_ip": "203.0.113.10",
  "user_agent": "Mozilla/5.0 ...",
  "issued_jti": null
}
```

---

## 20. 禁止事項

以下は禁止する。

```text
- login token を定義する
- tenant_access → tenant_access の Token Exchange
- event_access → tenant_access の Token Exchange
- event_access → event_access の Token Exchange
- tenant_id を scope に含める
- event_id を scope に含める
- x_tenant_id / x_event_id を使う
- role / tenant_role / event_role を JWT claim に入れる
- scope を暗黙に縮小して発行する
- 複数 audience の access token を発行する
- Opaque Token を使う
- Opaque Token Introspection に依存する
- access token 本体をログに出す
- revocation 監査ログに token 本体を出す
- relation service の詳細な失敗理由を外部レスポンスに出す
- relation service の失敗レスポンスを cache hit として扱う
```

---

## 21. 未確定事項

以下は未確定とし、後続設計で決める。

```text
- 具体的な Resource Server 分割
- 具体的な audience 名
- API path の最終形
- ユーザー認証後の tenant 選択フロー
- Resource Server ごとの permission 再確認ポリシー
- 本番 relation service で `admin` role を扱うか
```

---

## 22. 現行実装の設定デフォルト

```text
tolo-idp.issuer=http://localhost:8080
tolo-idp.resource.allowed-hosts=api.example.com
tolo-idp.relation.base-url=http://localhost:8081
tolo-idp.relation.connect-timeout=2s
tolo-idp.relation.read-timeout=3s
tolo-idp.relation.cache.ttl=5m
tolo-idp.relation.cache.admin-subjects=[]
tolo-idp.token.tenant-access-ttl=15m
tolo-idp.token.event-access-ttl=10m
```

seed data が有効な場合の開発用デフォルト:

```text
user=user-123
password=password
client_id=client-123
client_secret=secret
allowed_audience=backend-api
allowed_scopes=openid,tenant.read,tenant.write,tenant.claim,events.read,events.manage,events.operate,events.report
```

### 22.1 スコープ再設計に伴う移行

開発 seed が有効な場合、`client-123` の RegisteredClient の登録 scope と ClientPolicy の `allowed_scopes` を上記の開発用セットに同期する。既存の secret、TTL、audience、grant type などは保持し、登録済み redirect URI も保持したうえで開発用 URI を補う。他の client は変更しない。seed が無効な場合は作成・更新しない。

本番 client の自動移行や DB スキーマ変更は行わない。運用側で以下を実施する。

1. Resource Server と client の要求 scope を新しいスコープ用途に合わせて更新する。
2. 対象 client の `oauth2_registered_client.scopes` と `idp_client_policy.allowed_scopes` を両方更新し、`events.write` を削除する。`events.manage` / `events.operate` / `events.report` は必要なものを明示的に登録する。`tenant.claim` も利用する client にのみ登録する。
3. 新しい scope を要求して tenant_access token を再取得し、その scope の範囲内で event_access token を要求する。

既発行 JWT と保存済み authorization は変更・一括失効しない。旧 scope を新しい scope として解釈しない。交換元が旧 `events.write` のみを持つ場合、新イベントスコープへの交換は `invalid_grant` とする。交換要求自体に `events.write` が含まれる場合は `invalid_scope` とする。

---

## 23. 最終設計まとめ

```text
scope:
  何ができるか

resource:
  どの event に対する token を要求するか

tenant_id claim:
  どの tenant に対して発行された token か

event_id claim:
  どの event に対して発行された token か

role:
  Authorization Server が scope 発行時に使う内部情報
  relation service から取得する role は JWT claim に入れない

relation service:
  tenant / event の所属関係と subject user の role を返す
  現時点の暫定契約は tolo-relation-stub に合わせる

Authorization Server:
  tenant_access token を発行する
  tenant_access token から event_access token を発行する

Resource Server:
  JWT claim, scope, resource, path, DB を使って最終認可する
```
