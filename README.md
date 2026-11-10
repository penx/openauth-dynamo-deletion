# OpenAuth: `invalidate(subject)` deletes nothing with DynamoStorage

Minimal replication for `@openauthjs/openauth` 0.4.3.

With `DynamoStorage`, replaying a refresh token after the reuse window is
detected, but no refresh tokens are revoked. The token it was rotated into
keeps working. With `MemoryStorage`, the same steps revoke it.

## Run

Needs Node 22 or later and Docker.

```bash
npm install
npm run db      # DynamoDB Local, in another terminal
npm run repro
```

Output, after OpenAuth's request log lines:

```
MemoryStorage  replay: 400, rotated token after replay: 400  (revoked, as expected)
DynamoStorage  replay: 400, rotated token after replay: 200  (NOT revoked: bug)
```

## Cause

On reuse, `auth.invalidate(subject)` scans `["oauth:refresh", subject]` and
passes each returned key to `Storage.remove`:

- `DynamoStorage.scan` yields keys as `[pk, sk]`, where `pk` is
  `"oauth:refresh" + "\x1f" + subject`.
- `Storage.remove` runs `encode()`, which strips `\x1f` from every segment.
- So the `DeleteItem` key is `"oauth:refresh" + subject`, which doesn't exist,
  and nothing is deleted.

`MemoryStorage.scan` yields `splitKey(key)`, the original segments, so it
isn't affected.

## Possible fix

Have `DynamoStorage.scan` yield the original segments, as `MemoryStorage` does
(and import `splitKey` from `./storage`). With this change, both lines of the
output above say "revoked":

```ts
yield [[...splitKey(item[pk].S), ...splitKey(item[sk].S)], JSON.parse(item.value.S)]
```
