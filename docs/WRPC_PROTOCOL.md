# Kaspa wRPC JSON protocol: an implementer's spec

This spec is for a pure TypeScript client that speaks Kaspa wRPC over a WebSocket
using **JSON encoding** (no WASM, no Borsh).

Every claim below is checked against source code or against live mainnet traffic
captured on 2026-09-24. Source citations use `file:line`.

| Tag  | Source                                                                                                                                                    |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RK` | rusty-kaspa v2.1.0, commit `01b532e8` (`~/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e`)                                                     |
| `WR` | crate `workflow-rpc` **0.18.0** from crates.io. `RK/Cargo.toml:329` and `RK/Cargo.lock:8864-8866` pin this version. Paths are relative to the crate root. |
| `WS` | crate `workflow-websocket` 0.18.0 from crates.io (the server transport under `WR`)                                                                        |
| `WZ` | crate `workflow-serializer` 0.18.0 (in the local cargo registry)                                                                                          |

Live captures came from public mainnet nodes `wss://{kate.kaspa.red,luna.kaspa.blue,emma.kaspa.stream}/kaspa/mainnet/wrpc/json`,
which reported `serverVersion: "2.1.0"`. Two other nodes reported `2.0.1`. Captures are marked **LIVE**.

---

## 0. TL;DR for implementers

- Transport: one WebSocket, **text frames**, one JSON object per frame. There's no handshake and
  no hello message. Send requests right after `open`.
- Request: `{"id": <u64 number>, "method": "<camelCase op>", "params": <object>}`. `params` is
  **required**, even when it's `{}`.
- Success response: `{"id": <same>, "method": "<same>", "params": <result object>}`. **The result is in
  `params`, not in `result`.**
- Error response: `{"id": <same>, "method": "<same>", "error": {"code": 0, "message": "<text>", "data": null}}`.
  `code` is always `0`, so you can only tell errors apart by `message`.
- Notification (server to client): `{"method": "<camelCase>Notification", "params": {"<PascalCaseEventName>": {...}}}`.
  It has no `id`, and the payload is wrapped in an externally tagged enum.
- Subscribe with the `subscribe` op and the scope `{"UtxosChanged": {"addresses": [...]}}`. Don't use
  `notifyUtxosChanged`, which returns `RPC method not found`.
- If a frame fails to parse as the envelope, **the server drops the connection** without sending any
  error. Causes include invalid JSON, an unknown or misspelled method, a missing `params`, a
  non-u64 `id`, or a Borsh frame.
- u64 values go on the wire as bare JSON integers, **never strings**, and at full 64-bit precision.
  Strings are rejected. Use a bigint-aware JSON parser and serializer, because a mainnet address already
  holds 1.3e14 sompi (see §5).
- Hashes, txids, scripts, `payload` and `subnetworkId` are lowercase hex strings with no `0x` prefix.
  `scriptPublicKey` is a single hex string: `<version u16 big-endian, 4 hex chars><script hex>`, for
  example `"0000" + "20<32-byte pubkey>ac"`.
- Addresses are always sent **with** the prefix (`kaspa:...`). Without it you get `request deserialization error`.
- Public resolvers **only hand out Borsh URLs** (JSON returns HTTP 404). The public node proxies
  **do** accept JSON when you swap `/wrpc/borsh` for `/wrpc/json` in the URL the resolver returns (§6).

---

## 1. Framing

### 1.1 Envelope structs (`WR/src/messages.rs`)

```rust
// WR/src/messages.rs:10-16
pub struct JsonClientMessage<Ops, Id> {
    // pub jsonrpc: String,
    pub id: Option<Id>,
    pub method: Ops,
    pub params: Value,
}
// WR/src/messages.rs:29-42
pub struct JSONServerMessage<Ops, Id> {
    #[serde(skip_serializing_if = "Option::is_none")] pub id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")] pub method: Option<Ops>,
    #[serde(skip_serializing_if = "Option::is_none")] pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")] pub error: Option<JsonServerError>,
}
// WR/src/messages.rs:63-68
pub struct JsonServerError { code: u64, message: String, data: Option<Value> }
// WR/src/messages.rs:80-88: From<ServerError>: code: 0, message: err.to_string(), data: None
```

- **No version field.** There's no `jsonrpc`; it's commented out at `WR/src/messages.rs:12,20`. Unknown top-level fields are
  ignored. **LIVE:** `{"jsonrpc":"2.0","id":5,"method":"ping","params":{}}` returns `{"id":5,"method":"ping","params":{}}`.
- **`id`**: the server's Id type is `Id64` (`RK/rpc/wrpc/server/src/service.rs:121`, `RpcServer::new_with_encoding::<Server, Connection, RpcApiOps, Id64>`).
  `Id64` is a newtype over `u64` (`WR/src/id.rs:61-65`), so on the wire it's a **bare JSON unsigned integer**.
  **LIVE:** `0`, `9007199254740993` and `18446744073709551615` are all echoed back exactly. `-1`, `1.5` and `"7"`
  make the server **close the socket**. Use a small incrementing counter.
- **`id` absent or `null`** makes the frame a client-to-server _notification_: no response is ever sent (`WR/src/server/protocol/serde_json.rs:64,101-108`).
  The server has no client-notification handlers, so the frame is silently dropped. **LIVE:** `{"method":"ping","params":{}}` gets no reply.
- **`params` is required.** It's a non-optional `serde_json::Value` field. **LIVE:** `{"id":1,"method":"getServerInfo"}` **closes the socket**.
  For ops that take no arguments, send `{}`. `[]` also happens to work for empty structs. `null` gives
  `request deserialization error`.
- A success response echoes `id` and `method` and puts the result in `params` (`WR/src/server/protocol/serde_json.rs:71-77`).
- An error response echoes `id` and `method`, has no `params`, and carries `error` (`WR/src/server/protocol/serde_json.rs:87-93`).
  `data` is always emitted as `null` because it isn't `skip_serializing_if`.
- The client decodes like this (`WR/src/client/protocol/serde_json.rs:49-65`): if `error` is present, it's an error for `id`. Otherwise, if
  `id` is present, it's a success and `params` holds the result. If there's no `id` but `params` is present, it's a notification named by `method`.

### 1.2 Error codes and messages

`code` is **always `0`** (`WR/src/messages.rs:83`). The message is one of the following:

| Situation                                                                                                      | `message`                          | Source                                                                                           |
| -------------------------------------------------------------------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------ |
| Params don't deserialize into the request struct (missing field, wrong type, bad address, u64 as string, etc.) | `request deserialization error`    | `WR/src/server/interface/method.rs:95` → `ServerError::ReqDeserialize` (`WR/src/error.rs:54-55`) |
| Op exists in the `RpcApiOps` enum but has no handler (such as `notifyUtxosChanged`)                            | `RPC method not found`             | `WR/src/server/interface/mod.rs:121`, `WR/src/error.rs:44-45`                                    |
| The node's RpcError                                                                                            | `RpcError.to_string()` (free text) | `RK/rpc/macros/src/wrpc/server.rs:57-58` `.map_err(\|e\| ServerError::Text(e.to_string()))`      |

LIVE examples:

```json
{"id":14,"method":"getMempoolEntry","error":{"code":0,"message":"Transaction 0000000000000000000000000000000000000000000000000000000000000000 not found","data":null}}
{"id":18,"method":"submitTransaction","error":{"code":0,"message":"Rejected transaction e14b2c5a675421742452dcd84e02a04e06a4ae53968a4ed4c50a5d3e97448d9f: transaction e14b2c5a675421742452dcd84e02a04e06a4ae53968a4ed4c50a5d3e97448d9f is an orphan where orphan is disallowed","data":null}}
{"id":19,"method":"submitTransaction","error":{"code":0,"message":"RpcTransactionInput.sig_op_count is inconsistent with transaction version 1","data":null}}
{"id":23,"method":"submitTransactionReplacement","error":{"code":0,"message":"Rejected transaction e14b2c5a...8d9f: replace by fee found no double spending transaction in the mempool","data":null}}
{"id":101,"method":"notifyUtxosChanged","error":{"code":0,"message":"RPC method not found","data":null}}
{"id":24,"method":"getBalanceByAddress","error":{"code":0,"message":"request deserialization error","data":null}}
```

### 1.3 Frames that kill the connection

`WR/src/server/protocol/serde_json.rs:60-62` parses the frame into `JsonClientMessage<RpcApiOps, Id64>` and, on failure,
returns `WebSocketError::MalformedMessage`. The transport loop propagates that error with `?`
(`WS/src/server/mod.rs:238`, `self.handler.message(ctx, Message::Text(text), &sink_sender).await?;`), which ends
`connection_task`. **No error frame is sent.** The client sees close code `1006`.

LIVE, each of these closed the socket:

- non-JSON text
- unknown method (`"noSuchMethod"`, `"GetServerInfo"`, `"get_server_info"`)
- missing `params`
- `id` of `-1`, `1.5` or `"7"`

**Binary frames** on the JSON endpoint also fail, because `msg.into_text()` errors. So a client must never send
an op name it isn't sure the server knows. Pin to the op list in §2.

### 1.4 Ordering, concurrency, limits

- Requests on one connection are processed **sequentially**. kaspa constructs the server with
  `enable_async_handling = false` (`RK/rpc/wrpc/server/src/service.rs:121-127`, last argument `false`), and
  `WR/src/server/mod.rs:333-346` awaits `handle_message` inline in that case. So responses come back in request
  order. **LIVE:** three pipelined requests answered in order. Still match on `id`: **notifications interleave**
  with responses, and a response to `unsubscribe` can arrive after already-queued notifications.
- Max inbound message size is 128 MiB (`RK/rpc/wrpc/server/src/service.rs:16,149`).
- The server doesn't inspect the URL path (`WS/src/server/mod.rs:159`, `accept_async_with_config`). The paths used by the public
  proxies (`/kaspa/mainnet/wrpc/json`) are routing on their reverse proxy.
- There's no handshake. `RK/rpc/wrpc/server/src/service.rs:66-84` has the greeting handshake commented out.
- JSON object keys in responses come out **alphabetically sorted**. **LIVE:** results go through `serde_json::Value`
  maps without `preserve_order`. Don't depend on key order.
- The reference client's request timeout is 60 s, checked every 5 s (`WR/src/client/mod.rs:151-152`).

### 1.5 Keepalive

- **RPC `ping` op:** request `{"id":n,"method":"ping","params":{}}`, response `{"id":n,"method":"ping","params":{}}` (LIVE).
  `PingRequest {}` / `PingResponse {}` (`RK/rpc/core/src/model/message.rs:1786-1804`).
- WebSocket-level Ping frames are answered with Pong by the transport (`WS/src/server/mod.rs:243-252`). The server
  itself never sends pings and has no idle timer in this code. Browser and Node `WebSocket` APIs can't send ping
  frames, so if you need a keepalive through Cloudflare or nginx idle timeouts, send the RPC `ping` op, every 30 s for example.

---

## 2. Method names and op list

`RpcApiOps` is `#[serde(rename_all = "camelCase")]` (`RK/rpc/core/src/api/ops.rs:17-20`). On the wire, the method
is the camelCase variant name: `getUtxosByAddresses`, `submitTransaction`, `getServerInfo`. PascalCase and snake_case
are **rejected**, and the rejection closes the socket (§1.3).

API version constants: `RPC_API_VERSION = 1` and `RPC_API_REVISION = 0` (`RK/rpc/core/src/api/ops.rs:12,15`).
`getServerInfo` reports them. The reference client doesn't enforce them.

### 2.1 Ops with a registered handler (callable)

From the `Router` (`RK/rpc/wrpc/server/src/router.rs:30-82`), plus `subscribe` and `unsubscribe` (`router.rs:84-104`).
The wire name is followed by its `RpcApiOps` discriminant.

```
ping(110) addPeer(124) ban(139) estimateNetworkHashesPerSecond(142)
getBalanceByAddress(136) getBalancesByAddresses(137) getBlock(126) getBlockCount(130)
getBlockDagInfo(131) getBlocks(129) getBlockTemplate(118) getCurrentBlockColor(149)
getBlockRewardInfo(152) getCoinSupply(144) getConnectedPeerInfo(123)
getDaaScoreTimestampEstimate(145) getUtxoReturnAddress(150) getCurrentNetwork(116)
getFeeEstimate(147) getFeeEstimateExperimental(148) getHeaders(134) getInfo(141)
getMempoolEntries(122) getMempoolEntriesByAddresses(143) getMempoolEntry(121)
getMetrics(111) getConnections(113) getPeerAddresses(119) getServerInfo(114)
getSink(120) getSinkBlueScore(138) getSubnetwork(127) getSyncStatus(115)
getSystemInfo(112) getUtxosByAddresses(135) getVirtualChainFromBlock(128)
getVirtualChainFromBlockV2(151) getSeqCommitLaneProof(153) resolveFinalityConflict(132)
shutdown(133) submitBlock(117) submitTransaction(125) submitTransactionReplacement(146)
unban(140) subscribe(3) unsubscribe(4)
```

(Public nodes may restrict admin ops such as `shutdown`, `addPeer` and `ban`.)

### 2.2 Ops that exist in the enum but have **no** handler

The following ops return `RPC method not found` (LIVE for `notifyUtxosChanged`):
`noOp, connect, disconnect, notifyBlockAdded, notifyNewBlockTemplate, notifyUtxosChanged,
notifyPruningPointUtxoSetOverride, notifyFinalityConflict, notifyFinalityConflictResolved,
notifyVirtualDaaScoreChanged, notifyVirtualChainChanged, notifySinkBlueScoreChanged`
(`ops.rs:21-42`). The `notify*` ops are gRPC-style. **wRPC subscriptions go through `subscribe` / `unsubscribe`.**

### 2.3 Notification method names (server to client)

A notification's `method` is `RpcApiOps::from(EventType)` (`RK/rpc/core/src/api/ops.rs:176-189`), serialized in camelCase
(`RK/rpc/wrpc/server/src/connection.rs:159-161`):

| Event                       | wire `method`                             | discriminant |
| --------------------------- | ----------------------------------------- | ------------ |
| BlockAdded                  | `blockAddedNotification`                  | 60           |
| VirtualChainChanged         | `virtualChainChangedNotification`         | 61           |
| FinalityConflict            | `finalityConflictNotification`            | 62           |
| FinalityConflictResolved    | `finalityConflictResolvedNotification`    | 63           |
| UtxosChanged                | `utxosChangedNotification`                | 64           |
| SinkBlueScoreChanged        | `sinkBlueScoreChangedNotification`        | 65           |
| VirtualDaaScoreChanged      | `virtualDaaScoreChangedNotification`      | 66           |
| PruningPointUtxoSetOverride | `pruningPointUtxoSetOverrideNotification` | 67           |
| NewBlockTemplate            | `newBlockTemplateNotification`            | 68           |

The notification `params` is the `Notification` enum, serialized with serde's default **externally tagged** representation
with PascalCase variant names and no `rename_all` (`RK/rpc/core/src/api/notifications.rs:22-51`). So the payload is always
`{"<EventName>": { ...camelCase fields... }}`.

---

## 3. Subscriptions

### 3.1 `subscribe` / `unsubscribe`

The request `params` is a `Scope` (`RK/notify/src/scope.rs:35-49`). That's a serde enum **without** `rename_all`, so
it's externally tagged with **PascalCase** keys. The inner scope structs also have no `rename_all`, so any field names
stay **snake_case** (`scope.rs:89-92`, `156-159`).

| Scope                                                                                        | `params`                                                              |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| UtxosChanged                                                                                 | `{"UtxosChanged":{"addresses":["kaspa:..."]}}` (`[]` = all addresses) |
| VirtualDaaScoreChanged                                                                       | `{"VirtualDaaScoreChanged":{}}`                                       |
| SinkBlueScoreChanged                                                                         | `{"SinkBlueScoreChanged":{}}`                                         |
| BlockAdded                                                                                   | `{"BlockAdded":{}}`                                                   |
| VirtualChainChanged                                                                          | `{"VirtualChainChanged":{"include_accepted_transaction_ids":true}}`   |
| FinalityConflict / FinalityConflictResolved / PruningPointUtxoSetOverride / NewBlockTemplate | `{"<Name>":{}}`                                                       |

Responses: `subscribe` returns `SubscribeResponse { id: u64 }`, the connection's listener id
(`RK/rpc/core/src/model/message.rs:3661-3665`, `router.rs:89`). `unsubscribe` returns `{}` (`message.rs:3692-3694`).
Errors from `stop_notify` are swallowed (`router.rs:98-100`).

LIVE:

```json
>>> {"id":107,"method":"subscribe","params":{"VirtualDaaScoreChanged":{}}}
<<< {"id":107,"method":"subscribe","params":{"id":6619}}
<<< {"method":"virtualDaaScoreChangedNotification","params":{"VirtualDaaScoreChanged":{"virtualDaaScore":548264448}}}
<<< {"method":"virtualDaaScoreChangedNotification","params":{"VirtualDaaScoreChanged":{"virtualDaaScore":548264449}}}
>>> {"id":108,"method":"unsubscribe","params":{"VirtualDaaScoreChanged":{}}}
<<< {"method":"virtualDaaScoreChangedNotification","params":{"VirtualDaaScoreChanged":{"virtualDaaScore":548264450}}}
<<< {"id":108,"method":"unsubscribe","params":{}}

>>> {"id":111,"method":"subscribe","params":{"UtxosChanged":{"addresses":["kaspa:qru6qv0wyf7sl7qtwqkx7c03yhs244c2nwavxaszhrm8rmk5dtlvwztc5arzk","kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73"]}}}
<<< {"id":111,"method":"subscribe","params":{"id":6619}}
>>> {"id":112,"method":"unsubscribe","params":{"UtxosChanged":{"addresses":[...same...]}}}
<<< {"id":112,"method":"unsubscribe","params":{}}

>>> {"id":109,"method":"subscribe","params":{"SinkBlueScoreChanged":{}}}
<<< {"method":"sinkBlueScoreChangedNotification","params":{"SinkBlueScoreChanged":{"sinkBlueScore":546317881}}}
```

A camelCase scope key (`{"utxosChanged":...}`) returned `request deserialization error` (LIVE). A bare string
(`"VirtualDaaScoreChanged"`) can't deserialize a newtype variant under serde's externally tagged rules, so it's
rejected as well.

All subscriptions on a connection share one listener, so every `subscribe` returns the same `id` (LIVE: `6619`
three times). `UtxosChanged` address scopes are added and removed per call.

### 3.2 `utxosChangedNotification` payload

`UtxosChangedNotification { added: Vec<RpcUtxosByAddressesEntry>, removed: Vec<RpcUtxosByAddressesEntry> }`
(`RK/rpc/core/src/model/message.rs:3305-3310`, camelCase). The entry shape is the same as in `getUtxosByAddresses` (§4.7).
Removed entries **also carry a full `utxoEntry`**. LIVE (one element each):

```json
{
  "method": "utxosChangedNotification",
  "params": {
    "UtxosChanged": {
      "added": [
        {
          "address": "kaspa:qquu5ypnp3n0za4uu3dh89rftgnjzmlc3p4czx4la4nqd4lnw2n65fsq8y8le",
          "outpoint": {
            "index": 1,
            "transactionId": "d0045d6a8a22ef5a7b53066b7a40ecc094a3bd3b7deaf315d20ff654b2f06efd"
          },
          "utxoEntry": {
            "amount": 218267645,
            "blockDaaScore": 548264685,
            "covenantId": null,
            "isCoinbase": true,
            "scriptPublicKey": "00002039ca10330c66f176bce45b7394695a27216ff8886b811abfed6606d7f372a7aaac"
          }
        }
      ],
      "removed": [
        {
          "address": "kaspa:qrrw4vmfgkd4jd3hvajn4cfmtycw2vu2gg303cclfsxj45h4w3v0xt3nqrl6e",
          "outpoint": {
            "index": 0,
            "transactionId": "d0045d6a8a22ef5a7b53066b7a40ecc094a3bd3b7deaf315d20ff654b2f06efd"
          },
          "utxoEntry": {
            "amount": 218267645,
            "blockDaaScore": 548264684,
            "covenantId": null,
            "isCoinbase": true,
            "scriptPublicKey": "000020c6eab369459b59363767653ae13b5930e5338a4222f8e31f4c0d2ad2f57458f3ac"
          }
        }
      ]
    }
  }
}
```

### 3.3 Other notification payloads

- `VirtualDaaScoreChanged`: `{"virtualDaaScore": u64}` (`message.rs:3496-3500`)
- `SinkBlueScoreChanged`: `{"sinkBlueScore": u64}` (`message.rs:3417-3421`)
- `BlockAdded`: `{"block": RpcBlock}` (`message.rs:2985-2989`). `RpcBlock` is `{header, transactions, verboseData}`
  (`RK/rpc/core/src/model/block.rs:15-21`). The header keys are `hash, version, parentsByLevel, hashMerkleRoot, acceptedIdMerkleRoot,
utxoCommitment, timestamp (ms), bits, nonce, daaScore, blueWork, blueScore, pruningPoint` (`header.rs:34-49`).
  `blueWork` is a **big-endian hex string** of a Uint192 (`RK/math/src/uint.rs:844-848`), for example
  `"000000000000000000000000002fe9e93b006ced6f9f7a6d"`. `nonce` is a u64 and regularly exceeds 2^53
  (LIVE: `8142536400930671148`). Block `verboseData` keys: `hash, difficulty, selectedParentHash, transactionIds,
isHeaderOnly, blueScore, childrenHashes, mergeSetBluesHashes, mergeSetRedsHashes, isChainBlock`. Transactions use the §4.10 shape with `verboseData` filled.
- `VirtualChainChanged`: `{"removedChainBlockHashes":[hash],"addedChainBlockHashes":[hash],"acceptedTransactionIds":[{"acceptingBlockHash":hash,"acceptedTransactionIds":[txid]}]}`.
  LIVE (empty): `{"method":"virtualChainChangedNotification","params":{"VirtualChainChanged":{"acceptedTransactionIds":[],"addedChainBlockHashes":[],"removedChainBlockHashes":[]}}}`

---

## 4. Messages

Every struct below is `#[serde(rename_all = "camelCase")]` unless noted otherwise. `Option<T>` fields may be
omitted in requests (serde derive treats a missing `Option` as `None`). Every other field is **required**.

Encoding rules used in the tables:

| Rust type                                                  | JSON                                                                                                    | Source                                                                                                           |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `u64`, `u32`, `u16`, `u8`                                  | JSON integer (u64 at full precision, strings rejected)                                                  | serde default; LIVE                                                                                              |
| `f64`                                                      | JSON number (can be written as `1.66e+16`, `100.0` or `16621145027311346`)                              | LIVE                                                                                                             |
| `Hash`, `TransactionId`                                    | 64-char lowercase hex, byte order as stored (no reversal); uppercase accepted on input                  | `RK/crypto/hashes/src/lib.rs:48-49`, `RK/utils/src/serde_bytes_fixed_ref/ser.rs` (hex when human-readable); LIVE |
| `SubnetworkId`                                             | 40-char hex (20 bytes). Native is `"0000000000000000000000000000000000000000"`, coinbase is `"0100…00"` | `RK/consensus/core/src/subnets.rs:10,35-36`                                                                      |
| `Vec<u8>` with `hex::serde` (`signatureScript`, `payload`) | hex string, `""` for empty                                                                              | `RK/rpc/core/src/model/tx.rs:153,392`                                                                            |
| `ScriptPublicKey`                                          | **string** `hex(version as u16 BE) ++ hex(script)`                                                      | `RK/consensus/core/src/tx/script_public_key.rs:81-95` (ser), `301-313` (parse)                                   |
| `Address`                                                  | string `prefix:payload`; **prefix required**; lowercase only                                            | `RK/crypto/addresses/src/lib.rs:312-330`; LIVE                                                                   |
| `NetworkId`                                                | string `"mainnet"`, `"testnet-10"`, …                                                                   | `RK/consensus/core/src/network.rs:331-338`                                                                       |
| `NetworkType`                                              | string `"mainnet"`, `"testnet"`, `"devnet"`, `"simnet"`                                                 | `network.rs:31-39` (`rename_all = "lowercase"`)                                                                  |
| `Option<T>` in responses                                   | emitted as `null` when `None` (never omitted)                                                           | LIVE (`covenantId:null`, `verboseData:null`)                                                                     |

`ScriptPublicKey` input: a JSON **object** `{"version":0,"script":"<hex>"}` is also accepted
(`script_public_key.rs:225-289`, LIVE). But if `version` is a string, or `script` is a number, **the node task panics**
(`panic!("unexpected conversion")`, lines 245 and 256). **Always send the string form.**

### 4.1 `getServerInfo`

Request `{}` (`message.rs:2372-2374`). Response (`message.rs:2390-2400`):
`rpcApiVersion: u16, rpcApiRevision: u16, serverVersion: string, networkId: NetworkId, hasUtxoIndex: bool, isSynced: bool, virtualDaaScore: u64`.

LIVE:

```json
>>> {"id":1,"method":"getServerInfo","params":{}}
<<< {"id":1,"method":"getServerInfo","params":{"hasUtxoIndex":true,"isSynced":true,"networkId":"mainnet","rpcApiRevision":0,"rpcApiVersion":1,"serverVersion":"2.1.0","virtualDaaScore":548260860}}
```

### 4.2 `getInfo`

Request `{}` (`message.rs:246-248`). Response (`message.rs:264-274`): `p2pId: string, mempoolSize: u64, serverVersion: string,
isUtxoIndexed: bool, isSynced: bool, hasNotifyCommand: bool, hasMessageId: bool`.

```json
>>> {"id":2,"method":"getInfo","params":{}}
<<< {"id":2,"method":"getInfo","params":{"hasMessageId":true,"hasNotifyCommand":true,"isSynced":true,"isUtxoIndexed":true,"mempoolSize":0,"p2pId":"81f7a3c9-fd97-4bb7-aad1-fbd1398b90cc","serverVersion":"2.1.0"}}
```

### 4.3 `ping`, `getCurrentNetwork`, `getSyncStatus`, `getSinkBlueScore`

| op                  | request | response                   | source                 |
| ------------------- | ------- | -------------------------- | ---------------------- |
| `ping`              | `{}`    | `{}`                       | `message.rs:1786-1804` |
| `getCurrentNetwork` | `{}`    | `{"network": NetworkType}` | `message.rs:306-328`   |
| `getSyncStatus`     | `{}`    | `{"isSynced": bool}`       | `message.rs:2436-2458` |
| `getSinkBlueScore`  | `{}`    | `{"blueScore": u64}`       | `message.rs:1401-1423` |

```json
<<< {"id":3,"method":"ping","params":{}}
<<< {"id":4,"method":"getCurrentNetwork","params":{"network":"mainnet"}}
<<< {"id":5,"method":"getSyncStatus","params":{"isSynced":true}}
<<< {"id":7,"method":"getSinkBlueScore","params":{"blueScore":546314303}}
```

### 4.4 `getBlockDagInfo`

Request `{}`. Response (`message.rs:1041-1054`): `network: NetworkId, blockCount: u64, headerCount: u64, tipHashes: [Hash],
difficulty: f64, pastMedianTime: u64 (ms), virtualParentHashes: [Hash], pruningPointHash: Hash, virtualDaaScore: u64, sink: Hash`.

```json
<<< {"id":6,"method":"getBlockDagInfo","params":{"blockCount":1130713,"difficulty":1.6659022700194888e+16,"headerCount":1130713,"network":"mainnet","pastMedianTime":1790246266101,"pruningPointHash":"c857421bff821f7d8dd62c95c6e0a7aeb34d425720bdea198d4fe4a84b2039e9","sink":"82ea07e169fecd1864d8861b531e2c71072d856d099f37d0a0e11da8d7f34cde","tipHashes":["b00eeaec…8f33","…"],"virtualDaaScore":548260874,"virtualParentHashes":["82ea07e1…4cde","…"]}}
```

### 4.5 `getVirtualChainFromBlock`

Request (`message.rs:857-863`): `startHash: Hash, includeAcceptedTransactionIds: bool, minConfirmationCount?: u64`.
Response (`message.rs:894-900`): `removedChainBlockHashes: [Hash], addedChainBlockHashes: [Hash],
acceptedTransactionIds: [{acceptingBlockHash: Hash, acceptedTransactionIds: [TransactionId]}]` (`RpcAcceptedTransactionIds`, `tx.rs:650-655`).

```json
>>> {"id":17,"method":"getVirtualChainFromBlock","params":{"startHash":"82ea07e169fecd1864d8861b531e2c71072d856d099f37d0a0e11da8d7f34cde","includeAcceptedTransactionIds":false,"minConfirmationCount":0}}
<<< {"id":17,"method":"getVirtualChainFromBlock","params":{"acceptedTransactionIds":[],"addedChainBlockHashes":["4f72f7fc…f1d9","924bb5aa…2142","2a1d1ab2…c1ac","f4705a4c…ee50"],"removedChainBlockHashes":[]}}
```

`getVirtualChainFromBlockV2` (op 151) also exists; it's not covered here.

### 4.6 `getBalanceByAddress` / `getBalancesByAddresses`

- `getBalanceByAddress`: request `{"address": Address}` (`message.rs:1281-1285`). Response `{"balance": u64}` (`message.rs:1311-1315`).
- `getBalancesByAddresses`: request `{"addresses": [Address]}` (`message.rs:1341-1345`). Response
  `{"entries":[{"address": Address, "balance": u64 | null}]}` (`message.rs:1371-1375`, `RK/rpc/core/src/model/address.rs:36-43`).
  If **any** address is invalid, the whole request fails with `request deserialization error` (LIVE).
- Both need the node's `--utxoindex`. Check `getServerInfo.hasUtxoIndex`.

LIVE:

```json
>>> {"id":9,"method":"getBalanceByAddress","params":{"address":"kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73"}}
<<< {"id":9,"method":"getBalanceByAddress","params":{"balance":132695619913451}}

>>> {"id":100,"method":"getBalancesByAddresses","params":{"addresses":["kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73","kaspa:qru6qv0wyf7sl7qtwqkx7c03yhs244c2nwavxaszhrm8rmk5dtlvwztc5arzk"]}}
<<< {"id":100,"method":"getBalancesByAddresses","params":{"entries":[{"address":"kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73","balance":132695619913451},{"address":"kaspa:qru6qv0wyf7sl7qtwqkx7c03yhs244c2nwavxaszhrm8rmk5dtlvwztc5arzk","balance":287700514422294}]}}

>>> {"id":24,"method":"getBalanceByAddress","params":{"address":"qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73"}}
<<< {"id":24,"method":"getBalanceByAddress","error":{"code":0,"message":"request deserialization error","data":null}}
```

(`KASPA:QQKQ…` in uppercase was rejected too.)

### 4.7 `getUtxosByAddresses`

Request `{"addresses": [Address]}` (`message.rs:1449-1453`). `[]` returns `{"entries":[]}` (LIVE).
Response `{"entries": [RpcUtxosByAddressesEntry]}` (`message.rs:1479-1483`), where:

```
RpcUtxosByAddressesEntry (address.rs:8-14)
  address:   Address | null
  outpoint:  { transactionId: TransactionId(hex), index: u32 }        (tx.rs:96-102)
  utxoEntry: { amount: u64, scriptPublicKey: ScriptPublicKey(string),
               blockDaaScore: u64, isCoinbase: bool,
               covenantId: Hash | null }                              (tx.rs:23-31)
```

`covenantId` is the Toccata covenant id of the UTXO. It's `null` for ordinary UTXOs.

LIVE (the full response had 157 entries and 59,247 chars; the first three are shown):

```json
>>> {"id":8,"method":"getUtxosByAddresses","params":{"addresses":["kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73"]}}
<<< {"id":8,"method":"getUtxosByAddresses","params":{"entries":[
  {"address":"kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73","outpoint":{"index":0,"transactionId":"6abc7a29658326aa3194b9ea6d811357c27a788dfa771815179c097592fc8340"},"utxoEntry":{"amount":500000000,"blockDaaScore":23097751,"covenantId":null,"isCoinbase":false,"scriptPublicKey":"0000202c0b0a4c1f84e31b7234adb319ae970b6943592f0eae5e8513fcc476d0d211a5ac"}},
  {"address":"kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73","outpoint":{"index":0,"transactionId":"0c6ef4952aa0925e0db1423c51afcfa62afe5baf3a020f0bc82e01acf2a4b492"},"utxoEntry":{"amount":300000000000,"blockDaaScore":42061850,"covenantId":null,"isCoinbase":false,"scriptPublicKey":"0000202c0b0a4c1f84e31b7234adb319ae970b6943592f0eae5e8513fcc476d0d211a5ac"}},
  {"address":"kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73","outpoint":{"index":0,"transactionId":"e7853df278ddbd2b9ec567ea9ea17722e70ef8df284425d8a44d4f0e998757de"},"utxoEntry":{"amount":1999997931,"blockDaaScore":33922603,"covenantId":null,"isCoinbase":false,"scriptPublicKey":"0000202c0b0a4c1f84e31b7234adb319ae970b6943592f0eae5e8513fcc476d0d211a5ac"}},
  …]}}
```

`scriptPublicKey` `"0000" + "20" + <32-byte x-only pubkey> + "ac"` is version 0 followed by `OP_DATA_32 <pk> OP_CHECKSIG` (P2PK Schnorr).

### 4.8 `getFeeEstimate` / `getFeeEstimateExperimental`

`getFeeEstimate`: request `{}` (`message.rs:2535-2537`). Response `{"estimate": RpcFeeEstimate}` (`message.rs:2553-2557`):

```
RpcFeeEstimate (feerate_estimate.rs:15-35)
  priorityBucket: RpcFeerateBucket
  normalBuckets:  [RpcFeerateBucket]     first element always present (sub-minute)
  lowBuckets:     [RpcFeerateBucket]     first element always present (sub-hour)
RpcFeerateBucket (feerate_estimate.rs:5-13): { feerate: f64 (sompi/gram), estimatedSeconds: f64 }
```

The fee is `feerate × mass(tx)`, per the doc comment at `feerate_estimate.rs:20-22`.

```json
>>> {"id":11,"method":"getFeeEstimate","params":{}}
<<< {"id":11,"method":"getFeeEstimate","params":{"estimate":{"lowBuckets":[{"estimatedSeconds":0.0023785347879217308,"feerate":100.0}],"normalBuckets":[{"estimatedSeconds":0.0023785347879217308,"feerate":100.0},{"estimatedSeconds":0.0023785347879217308,"feerate":100.0}],"priorityBucket":{"estimatedSeconds":0.0023785347879217308,"feerate":100.0}}}}
```

`getFeeEstimateExperimental`: request `{"verbose": bool}` (`message.rs:2575-2579`, required). The response adds
`verbose: {mempoolReadyTransactionsCount: u64, mempoolReadyTransactionsTotalMass: u64, networkMassPerSecond: u64,
nextBlockTemplateFeerateMin: f64, nextBlockTemplateFeerateMedian: f64, nextBlockTemplateFeerateMax: f64} | null`
(`message.rs:2597-2605`, `feerate_estimate.rs:66-76`). **LIVE:** the three `nextBlockTemplateFeerate*` f64 values come
back as `null`. serde_json writes NaN and Infinity as `null`, so those fields need `number | null` types.

```json
<<< {"id":12,"method":"getFeeEstimateExperimental","params":{"estimate":{…same shape…},"verbose":{"mempoolReadyTransactionsCount":1,"mempoolReadyTransactionsTotalMass":1966,"networkMassPerSecond":5000000,"nextBlockTemplateFeerateMax":null,"nextBlockTemplateFeerateMedian":null,"nextBlockTemplateFeerateMin":null}}}
```

### 4.9 Mempool: `getMempoolEntry`, `getMempoolEntries`, `getMempoolEntriesByAddresses`

- `getMempoolEntry` request (`message.rs:447-454`): `transactionId: TransactionId, includeOrphanPool: bool, filterTransactionPool: bool` (all required).
  Response `{"mempoolEntry": RpcMempoolEntry}` (`message.rs:484-488`).
- `getMempoolEntries` request: `includeOrphanPool: bool, filterTransactionPool: bool`. Response `{"mempoolEntries":[RpcMempoolEntry]}`.
- `getMempoolEntriesByAddresses` request (`message.rs:1668-1675`): `addresses: [Address], includeOrphanPool: bool, filterTransactionPool: bool`.
  Response `{"entries": [RpcMempoolEntryByAddress]}` (`message.rs:1705-1709`).

**Quirk:** `RpcMempoolEntry` and `RpcMempoolEntryByAddress` have **no `rename_all`** (`RK/rpc/core/src/model/mempool.rs:6-11,36-41`), so the key is
**`is_orphan`** in snake_case (LIVE):

```
RpcMempoolEntry          { fee: u64, transaction: RpcTransaction, is_orphan: bool }
RpcMempoolEntryByAddress { address: Address, sending: [RpcMempoolEntry], receiving: [RpcMempoolEntry] }
```

LIVE:

```json
>>> {"id":13,"method":"getMempoolEntriesByAddresses","params":{"addresses":["kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73"],"includeOrphanPool":false,"filterTransactionPool":false}}
<<< {"id":13,"method":"getMempoolEntriesByAddresses","params":{"entries":[{"address":"kaspa:qqkqkzjvr7zwxxmjxjkmxxdwju9kjs6e9u82uh59z07vgaks6gg62v8707g73","receiving":[],"sending":[]}]}}

>>> {"id":16,"method":"getMempoolEntry","params":{"transactionId":"f32c5eca06322a8fd17b47933d28a055f8cb504790a2c0b981a151da4e317472","includeOrphanPool":false,"filterTransactionPool":false}}
<<< {"id":16,"method":"getMempoolEntry","params":{"mempoolEntry":{"fee":2000000,"is_orphan":false,"transaction":{"gas":0,"inputs":[{"computeBudget":0,"previousOutpoint":{"index":0,"transactionId":"28dc4e8c320f209587a9a835170f610a95029fdfe959234a5632edf9b34a5653"},"sequence":0,"sigOpCount":1,"signatureScript":"4132ffb9b82ff4fa6443eea688a101f0b5e8f21b992b39d81be81d9c5b73323e2c4ff39f67dc8c5dc986f177918e70e3b34bfc5042bdc6776faef4ec19f6d40e1a01","verboseData":null}],"lockTime":0,"mass":0,"outputs":[{"covenant":null,"scriptPublicKey":"000020f9a031ee227d0ff80b702c6f61f125e0aad70a9bbac37602b8f671eed46afec7ac","value":183497836400,"verboseData":{"scriptPublicKeyAddress":"kaspa:qru6qv0wyf7sl7qtwqkx7c03yhs244c2nwavxaszhrm8rmk5dtlvwztc5arzk","scriptPublicKeyType":"PubKey"}}],"payload":"","storageMass":0,"subnetworkId":"0000000000000000000000000000000000000000","verboseData":{"blockHash":"0000000000000000000000000000000000000000000000000000000000000000","blockTime":0,"computeMass":1624,"hash":"9c2ce5e3d9b258ac7feb7b9ddf406c2e6cbd58b7700b1ba18906338ea97958b7","transactionId":"f32c5eca06322a8fd17b47933d28a055f8cb504790a2c0b981a151da4e317472"},"version":0}}}}

>>> {"id":14,"method":"getMempoolEntry","params":{"transactionId":"0000000000000000000000000000000000000000000000000000000000000000","includeOrphanPool":true,"filterTransactionPool":false}}
<<< {"id":14,"method":"getMempoolEntry","error":{"code":0,"message":"Transaction 0000000000000000000000000000000000000000000000000000000000000000 not found","data":null}}
```

Mempool entries report `mass: 0` / `storageMass: 0`, and blocks do the same. **Don't read mass from RPC output.**
`verboseData.computeMass` is filled in.

### 4.10 The transaction model (`RpcTransaction`), including v1 / Toccata

`RpcTransaction` has a hand-written serde implementation (`RK/rpc/core/src/model/tx.rs:366-460`). It goes through
`RpcTransactionHumanReadable` (`tx.rs:383-397`, camelCase). JSON-only: Borsh-style non-human-readable serde errors out (`tx.rs:404-406,439-441`).

```
RpcTransaction (JSON)
  version:      u16                          0 = legacy, >=1 = compute-budget inputs (Toccata)
  inputs:       [RpcTransactionInput]
  outputs:      [RpcTransactionOutput]
  lockTime:     u64
  subnetworkId: hex(20 bytes)                "0000000000000000000000000000000000000000" = native
  gas:          u64                          0 for native subnetwork
  payload:      hex string                   "" when empty
  storageMass:  u64 | omitted                } at least one is REQUIRED on input; if both are
  mass:         u64 | omitted                } present they must be equal (tx.rs:409-418).
                                               Output always emits both, equal (tx.rs:454-455).
  verboseData:  RpcTransactionVerboseData | null   (optional on input; ignored)

RpcTransactionInput (tx.rs:149-160)
  previousOutpoint: { transactionId: hex32, index: u32 }
  signatureScript:  hex string
  sequence:         u64
  sigOpCount:       u8          REQUIRED FIELD in JSON even for v1 (no serde default); must be 0 when version>=1
  computeBudget:    u16         #[serde(default)] -> optional, default 0; must be 0 when version==0
  verboseData:      {} | null   optional

RpcTransactionOutput (tx.rs:242-249)
  value:           u64
  scriptPublicKey: ScriptPublicKey string
  verboseData:     { scriptPublicKeyType: string, scriptPublicKeyAddress: Address } | null   (optional on input)
  covenant:        { authorizingInput: u16, covenantId: hex32 } | null                         (optional)
                   (RpcCovenantBinding is a transparent newtype around CovenantBinding,
                    tx.rs:291-293; CovenantBinding is camelCase, RK/consensus/core/src/tx.rs:190-196)

RpcTransactionVerboseData (tx.rs:613-621)
  transactionId: hex32, hash: hex32, computeMass: u64, blockHash: hex32, blockTime: u64 (ms)
```

**Version and compute-commit rule.** When the RPC tx is converted to a consensus tx (`RK/rpc/core/src/convert/tx.rs:19-41`):

```rust
if ComputeCommit::version_expects_compute_budget_field(value.version) {   // version >= 1 (consensus/core/src/tx.rs:91-93)
    if value.input.sig_op_count != 0 { return Err("RpcTransactionInput.sig_op_count is inconsistent with transaction version {v}") }
    ComputeBudget(value.input.compute_budget).into()
} else {
    if value.input.compute_budget != 0 { return Err("RpcTransactionInput.compute_budget is inconsistent with transaction version {v}") }
    SigopCount(value.input.sig_op_count).into()
}
```

Here's how to express a v1 transaction with a compute budget, exactly:

```json
{
  "version": 1,
  "inputs": [
    {
      "previousOutpoint": { "transactionId": "<64 hex>", "index": 0 },
      "signatureScript": "41<64-byte schnorr sig><sighash type byte>",
      "sequence": 0,
      "sigOpCount": 0,
      "computeBudget": 10
    }
  ],
  "outputs": [
    { "value": 6884599629, "scriptPublicKey": "000020<32-byte pubkey>ac" }
  ],
  "lockTime": 0,
  "subnetworkId": "0000000000000000000000000000000000000000",
  "gas": 0,
  "payload": "",
  "mass": 0
}
```

Units (`RK/consensus/core/src/mass/units.rs:4-7,22-24`): one compute-budget unit is 100 grams, which is
10,000 script units. Each input also gets a free `10,000 − 1` script units. A legacy `sigOpCount` unit is
1,000 grams, so `computeBudget: 10` is the v1 equivalent of `sigOpCount: 1`. That's what live mainnet P2PK
spends use; see the real v1 tx below.

For v1 transaction ids, `computeBudget` sits under `EXCLUDE_MASS_COMMIT` (`RK/consensus/core/src/hashing/tx.rs:112-114`), so it
**does not change the txid**. **LIVE:** the same tx with `computeBudget` 10 and with it omitted (0) was rejected under the same id `5dd632be…7295`.

A real mainnet **v1** transaction, captured LIVE from a `blockAddedNotification`:

```json
{
  "gas": 0,
  "inputs": [
    {
      "computeBudget": 10,
      "previousOutpoint": {
        "index": 0,
        "transactionId": "97b1fd88412ccb755fd903fcbb46cc3164e2a967ccf9abcad59e014c087790da"
      },
      "sequence": 0,
      "sigOpCount": 0,
      "signatureScript": "41639e7dc2b17637a8ef240628d2326f1eb52a3da47bc4cd24a23051fa6bfdde594dec2cdb8f27ade0d1c6368a19f0dd05f1d3d350bf6affe4cbffa01843e8cad601",
      "verboseData": null
    }
  ],
  "lockTime": 0,
  "mass": 0,
  "outputs": [
    {
      "covenant": null,
      "scriptPublicKey": "000020097f751d200b516cd67b3b9ed855b74011511293e5c2d9c666ff0bbaae716431ac",
      "value": 6884599629,
      "verboseData": {
        "scriptPublicKeyAddress": "kaspa:qqyh7agayq94zmxk0vaeakz4kaqpz5gjj0ju9kwxvmlshw4ww9jrzkuvxn85t",
        "scriptPublicKeyType": "PubKey"
      }
    }
  ],
  "payload": "95789c85…0f44",
  "storageMass": 0,
  "subnetworkId": "97b1000000000000000000000000000000000000",
  "verboseData": {
    "blockHash": "6ea1235dc2e7077bfcfa472ced8abf7d62d5f8e163dc73fdcbf595b86190d572",
    "blockTime": 1790246791018,
    "computeMass": 1962,
    "hash": "d39767f80ba5161da3d7cfa29fd2d2e3cfc70d67a0a264e57ce5416889b84bd4",
    "transactionId": "97b198364019bc37d1a5b4a3bb61b79e02262e0eed874947fafa44a5d8a6c143"
  },
  "version": 1
}
```

Coinbase transactions are v1 on mainnet now as well, with subnetworkId `0100…00`.

**Storage mass on submit.** The mempool recomputes the contextual storage mass and **overwrites** the field
before validating (`RK/consensus/src/pipeline/virtual_processor/utxo_validation.rs:428-451`, `set_storage_mass(...)`,
then `TxValidationFlags::SkipMassCheck`). So the value you send in `mass` / `storageMass` doesn't matter for mempool
acceptance, but **one of the two keys must be present**. Send `"mass": 0`, or the value you computed. Blocks
enforce the commitment (`tx_validation_in_utxo_context.rs:126-133`), but that only concerns miners.

### 4.11 `submitTransaction`

Request (`message.rs:671-676`): `{"transaction": RpcTransaction, "allowOrphan": bool}`, with **`allowOrphan` required**.
Response (`message.rs:704-708`): `{"transactionId": TransactionId}`.

A success looks like `{"id":n,"method":"submitTransaction","params":{"transactionId":"<hex>"}}`. That shape comes from
the struct; it wasn't captured, because a live success would need a funded spend.

LIVE rejections (fake outpoint):

```json
>>> {"id":20,"method":"submitTransaction","params":{"transaction":{"version":1,"lockTime":0,"subnetworkId":"0000000000000000000000000000000000000000","gas":0,"payload":"","mass":0,"inputs":[{"previousOutpoint":{"transactionId":"1111111111111111111111111111111111111111111111111111111111111111","index":0},"signatureScript":"41000000…00","sequence":0,"sigOpCount":0,"computeBudget":10}],"outputs":[{"value":1000,"scriptPublicKey":"0000202222222222222222222222222222222222222222222222222222222222222222ac"}]},"allowOrphan":false}}
<<< {"id":20,"method":"submitTransaction","error":{"code":0,"message":"Rejected transaction 5dd632be5c2f044347597abeb65db6fb4b638edf29e74a853fd4672386b67295: transaction 5dd632be5c2f044347597abeb65db6fb4b638edf29e74a853fd4672386b67295 is an orphan where orphan is disallowed","data":null}}
```

Serde behavior verified LIVE against `submitTransaction`:

| Variation                                                    | Result                                                                          |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `storageMass` instead of `mass`                              | accepted by serde                                                               |
| neither `mass` nor `storageMass`                             | `request deserialization error`                                                 |
| `mass: 5, storageMass: 6`                                    | `request deserialization error`                                                 |
| v1 input without `sigOpCount` key                            | `request deserialization error`                                                 |
| v1 input without `computeBudget` key                         | accepted (budget = 0)                                                           |
| v1 with `sigOpCount: 1`                                      | `RpcTransactionInput.sig_op_count is inconsistent with transaction version 1`   |
| v0 with `computeBudget: 10`                                  | `RpcTransactionInput.compute_budget is inconsistent with transaction version 0` |
| `computeBudget: 65536`                                       | `request deserialization error` (u16 overflow)                                  |
| `sequence: 18446744073709551615`                             | accepted (u64::MAX exactly)                                                     |
| `value: "1000"` (string)                                     | `request deserialization error`                                                 |
| `subnetworkId: "00"`                                         | `request deserialization error`                                                 |
| `scriptPublicKey: {"version":0,"script":"20…ac"}`            | accepted (same txid as the string form)                                         |
| output `covenant: {"authorizingInput":0,"covenantId":"33…"}` | accepted by serde                                                               |

`allowOrphan: true` was still rejected with "orphan is disallowed" on the public node, so treat orphans as unsupported.

### 4.12 `submitTransactionReplacement` (RBF)

Request (`message.rs:734-738`): `{"transaction": RpcTransaction}`, with no `allowOrphan`.
Response (`message.rs:764-769`): `{"transactionId": TransactionId, "replacedTransaction": RpcTransaction}`.

```json
<<< {"id":23,"method":"submitTransactionReplacement","error":{"code":0,"message":"Rejected transaction e14b2c5a…8d9f: replace by fee found no double spending transaction in the mempool","data":null}}
```

---

## 5. Serde and number quirks

1. **u64 is a JSON number, and nothing else.** No u64 field in the model uses a string serializer. The only
   exceptions are the fields listed in §4 as hex. A JSON string for a u64 gives `request deserialization error`
   (LIVE). serde's u64 deserializer also rejects floats (`1.5`, `1e3`) and negative numbers.
2. **Full 64-bit precision both ways.** The request is parsed into a `serde_json::Value` first
   (`WR/src/messages.rs:15`), then into the struct (`WR/src/server/interface/method.rs:95`). rusty-kaspa doesn't
   enable serde_json's `arbitrary_precision` (`RK/Cargo.toml:259`: `serde_json = "1.0.107"`, no features), but
   `Value` keeps integers as exact `u64`/`i64` anyway. Responses write u64 values exactly, so **numbers above
   2^53 − 1 are emitted.** LIVE: `id` `9007199254740993` and `18446744073709551615` round-tripped exactly, and a block
   header `nonce` came back as `8142536400930671148`.
3. **Consequences for JS.** `JSON.parse` silently rounds integers above 2^53. At risk:
   - `amount`, `value`, `balance`, `fee` (sompi). 2^53 sompi is about 90 million KAS, and one address here already
     holds 1.33e14 sompi. Exchange and treasury wallets can exceed 2^53.
   - `nonce` in headers (always large)
   - `sequence` (u64, sometimes `u64::MAX`)
   - `gas`, `lockTime`

   Parse with a lossless parser. Options include the `reviver` with `context.source` (Node 21+ and modern
   browsers: `JSON.parse(text, (k, v, ctx) => …BigInt(ctx.source)…)`) or a small custom tokenizer. When
   serializing, write bigint as a **bare number**, never `"123"`, never `123n`, and never `Number(big)`.
   `JSON.rawJSON(big.toString())` (Node 21+) or string templating works.

4. **`f64` fields** (`difficulty`, `feerate`, `estimatedSeconds`, the `nextBlockTemplateFeerate*` values) can be
   `null` when not finite, and may be printed in exponent form or without a decimal point. Type them as `number | null`.
5. **`Option<T>` in responses** is always present, as `null` when None. In requests it may be omitted.
6. **Unknown fields are ignored.** No RPC model uses `deny_unknown_fields`; the only uses in `RK/consensus/core/src` are config and mass internals.
7. **Hex input accepts uppercase.** LIVE: an uppercase txid was echoed back lowercased in the error message. Output is always lowercase.
8. **Addresses** must include the prefix and be lowercase (`Address::try_from(&str)` splits on `:`, `RK/crypto/addresses/src/lib.rs:315-320`).
9. **The JS WASM SDK types u64 as `bigint`** (for example `balance : bigint` at `RK/rpc/core/src/wasm/message.rs:690`,
   `virtualDaaScore: bigint` at `:170`). That's the SDK's JS object view (serde-wasm-bindgen). The wire JSON is plain
   numbers. The SDK's JS shapes otherwise match the wire field names above.

---

## 6. Endpoints, ports and the resolver

### 6.1 Ports and encodings

`RK/consensus/core/src/network.rs:41-67`:

| network | gRPC  | wRPC Borsh | wRPC JSON |
| ------- | ----- | ---------- | --------- |
| mainnet | 16110 | **17110**  | **18110** |
| testnet | 16210 | 17210      | 18210     |
| simnet  | 16510 | 17510      | 18510     |
| devnet  | 16610 | 17610      | 18610     |

The encoding is per listener, not per URL. kaspad runs one wRPC listener per encoding, set by `--rpclisten-borsh` and
`--rpclisten-json` (`RK/kaspad/src/args.rs:259-277`, `RK/kaspad/src/daemon.rs:747-748`). **Both are off by default**
(`args.rs:109-110`, `None`). Passing the flag with no value uses the default port above
(`RK/rpc/wrpc/server/src/address.rs:16-38`). The workflow encoding names are `"borsh"` and `"json"`
(`WR/src/encoding.rs:19-23,36-46`).

Client URL defaulting (`RK/rpc/wrpc/client/src/client.rs:512-550`): a bare host gets `ws://host:<default port for encoding>`.
If the URL has a scheme or a path, the port isn't added.

### 6.2 Resolver protocol

Source: `RK/rpc/wrpc/client/src/resolver.rs`.

- Query URL (`resolver.rs:16,126-143`): `GET {resolver}/v2/kaspa/{networkId}/{tls|any}/wrpc/{borsh|json}`.
  `CURRENT_VERSION = 2`. `networkId` is `mainnet`, `testnet-10`, and so on. Use `tls` for a `wss://` node; the native default is `any`, and in a browser on `https` the SDK forces `tls`.
- Response (`RK/rpc/wrpc/client/src/node.rs:11-20`): JSON `{"uid": string, "url": string}`. `url` is the wRPC WebSocket URL.
- The client shuffles the resolver list and uses the first one that answers (`resolver.rs:155-167`).
- Resolver hosts come from `RK/rpc/wrpc/client/Resolvers.toml`, expanded as `template.replace('*', node)` (`resolver.rs:51-56`):

```
https://{eric,maxim,sean,troy}.kaspa.stream
https://{john,mike,paul,alex}.kaspa.red
https://{jake,mark,adam,liam}.kaspa.green
https://{noah,ryan,jack,luke}.kaspa.blue
```

(`http://127.0.0.1:8888` is present but `enable = false`. The `kaspa-ng.*` groups are commented out.)

**LIVE findings (2026-09-24):**

```
$ curl https://luke.kaspa.blue/v2/kaspa/mainnet/any/wrpc/borsh
{"uid":"4642164ea14fe73a","url":"wss://kate.kaspa.red/kaspa/mainnet/wrpc/borsh"}
$ curl https://luke.kaspa.blue/v2/kaspa/mainnet/tls/wrpc/borsh
{"uid":"8e0a3992f73dc945","url":"wss://luna.kaspa.blue/kaspa/mainnet/wrpc/borsh"}
$ curl https://luke.kaspa.blue/v2/kaspa/mainnet/any/wrpc/json
NOT FOUND                                    (HTTP 404, on every reachable resolver)
$ curl https://luke.kaspa.blue/v2/kaspa/testnet-10/any/wrpc/borsh
{"uid":"b5061c7c25dd77ba","url":"wss://muon-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh"}
testnet-11 / testnet-12: 404 for both encodings
```

- Reachability of the 16 resolvers varied. Reachable ones (`eric`, `maxim`, `troy`, `john`, `mike`, `alex`, `mark`, `jack`, `luke`)
  answered 200. `paul.kaspa.red` returned 523 and `jake.kaspa.green` returned 204 with an empty body. Several others
  (`sean`, `adam`, `liam`, `noah`, `ryan`) failed at the transport level. Try them in random order, treat anything but
  200 with a parseable body as a failure, and move on to the next.
- **The public resolvers never return a JSON node.** The node proxies behind them **do** serve JSON at the same path
  with `/json`: `wss://{kate.kaspa.red,luna.kaspa.blue,emma.kaspa.stream,isla.kaspa.red,ivy.kaspa.green}/kaspa/mainnet/wrpc/json`
  all answered `getServerInfo` in JSON. So the practical recipe for a JSON client is:
  1. `GET https://<random resolver>/v2/kaspa/mainnet/tls/wrpc/borsh` returns `{uid, url}`.
  2. Replace a trailing `/wrpc/borsh` in `url` with `/wrpc/json`, and connect.
  3. Call `getServerInfo` to verify `networkId`, `isSynced` and `hasUtxoIndex`. If the call fails, try the next resolver.

  This relies on how the public proxies are deployed today, not on anything in rusty-kaspa. For production, point at
  your own kaspad with `--utxoindex --rpclisten-json=0.0.0.0:18110`, and keep the resolver as a fallback.

- Opening many sockets in quick succession to one proxy sometimes failed the upgrade (error before `open`). A retry
  against another node succeeded. Build in retry and failover.

---

## 7. Minimal client checklist

1. Resolve the URL (§6.2) or use your own node. Open the WebSocket and send only text frames.
2. Keep `id` as an incrementing integer in the u32 range, and a `Map<id, pending>` with your own timeout (the reference client uses 60 s).
3. For each incoming frame, parse it losslessly (bigint-safe). If `id` is present: `error` means reject, otherwise
   resolve with `params`. If `id` is absent: it's a notification. Dispatch on `method`, then unwrap the single key of `params`.
4. Only send op names from §2.1. A bad name kills the socket, so reconnect and re-subscribe on close.
5. On reconnect, replay `subscribe` calls. Subscriptions are per connection (the listener is created per connection, `RK/rpc/wrpc/server/src/server.rs:175-187`).
6. Send `ping` periodically as a keepalive.
