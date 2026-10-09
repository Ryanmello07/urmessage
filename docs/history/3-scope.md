# Stage 3: what the move could narrow, and what was measured

The messaging SDK came from the core SDK, where it shared `package sdk` and the module root
with the VPN SDK. Every gate that read "every production file of package sdk", or walked the
core SDK's module root, read core files too. Here `package sdk` is the messaging SDK alone
(`github.com/urnetwork/message/sdk`), and the module sits nested under this repository's root,
where the root module's walks meet it. This file records, for every such gate, what it read
before and what it reads now, and who keeps each half the move left behind. Each change
named here is one commit on the branch, with its controls in the commit message.

Measured on Windows (go1.26.5) unless marked; "P_sdk" is the source,
`Ryanmello07/urnetwork-sdk` `6141b98d`.

## 1. The gates that read package sdk

| Gate | In the core SDK | Here | Disposition |
|---|---|---|---|
| Value census (`message_stream_adapter_test.go`) | 182 entries, core and messaging | 42 entries plus the 2 Windows constants: 44 named values on windows, 0 out of reach | A declared change of subject: the census holds this package's values. Still both ways over this package's syntax tree. |
| Native-extender census fragments | one value, `device_local_extender_native.go`'s | deleted | The file is the core SDK's. |
| Non-sentinel rulings | 23 core errors among its rows | removed | Each core error is the core's; the both-ways check named every one. |
| `streamStoreSyncRulings` | 4 core Syncs | empty | forceFlush is again the package's only Sync, as before the core's merge. |
| Part-size copy rulings | 6 portable, 1 linux, 1 darwin expression ruling: all core files | empty (the platform halves stay, empty) | `TestPartSizeExclusiveFlagRulingTracksPlatformValue` removed with its subject; the expression-key rule is held over a fixture. |
| Code-point gate (`TestMessageTransportReadsOnlyTheCodePointsThatAreItsOwn`) | keyed on the local name `protocol` | the package of the receive path's own import of `connect/protocol` | The schema switch renamed the import; the gate now follows the import path. |
| Borrow gate C2 | "today contains two" registrations other than the binding's | one, MessageClient's forward | Printed, not asserted, as before; the set is held by the new audit. |
| Receive-callback audit | the core's `device_receive_callback_policy_test.go`, 3 registrations | `TestSdkClientReceiveRegistrationsAreAudited`, 2 | Rebuilt here. The core keeps its own, at 1 (the sdk removal PR). |
| Crypto scope | none: connect's scan roots excluded the SDK | `TestThisModulesProductionCryptoImportsAreTheDeclaredOnes`: 11 files, sha256, subtle, tls, rand | New. Every production file under `sdk/`, nested modules included; 25 test files printed as the complement. |

## 2. The gates that walk the module root

`moduleRoot` finds the nearest `go.mod`, which was the core SDK's root and is `sdk/` here.

| Gate | In the core SDK | Here | Disposition |
|---|---|---|---|
| Test-citation gate | declarations and prose of the core module; 7 cited names carved out (6 in connect, 1 in msgrepo) | declarations from the whole repository (385 files), prose of this module (36 production files) | The 6 connect names are declared here now and their carve-outs are deleted; TestMain's carve-out is emptied (its 3 citations were core files). The complement is printed: the root module's prose cites 206 names, 4 unresolved (3 wrapped across lines, 1 message-server test), not asserted. |
| Godoc-link gate | declarations from every file; prose of `urmessageOwns` (URmessage's files) | every production file, 36 | The narrowing is removed; `cgo/loopback_test_world.go`, which it missed, is read. The 18 `[sdk.X]` links resolve to this module's package sdk. |
| pqdarkgate, `TestNoProductionCommentClaimsADarkGroupRepairsItself` | 255 production files at P_sdk, 0 hits | 36 production files, 0 hits | The non-moved half is out of subject, measured at P_sdk: 219 core production files, none holding any of the gate's claim phrases. `mustScan` paths are unchanged, relative to the sdk module. |
| pqdarkgate, `TestTheRemovalRuleIsDocumentedAsAReceiverPropertyAndNeverAsAGroupOne` | 255 files, 13 comment blocks and 4 literals in subject | the same 13 and 4 | Out of subject, measured: no core production file names `pq_secret`; the 13 files that do all moved. |
| Removal bookkeeping | `<module root>/urmessage` | the same path under the sdk module | Unchanged. |

## 3. The root module's walks, which now meet `sdk/`

| Walk | Disposition | Measured |
|---|---|---|
| mls crypto derivation and its `go list` floor | stops at a nested `go.mod`; the floor is `go list` over the root module | 5 packages walked, component [message messagegroup mls syntax], class [message messagegroup mls], out of scope: [sdk]; before the stop the floor failed |
| writeauth importer gate | stops at a nested `go.mod`; the nested modules' importers are printed | importers [messagegroup]; complement: sdk/urmessage imports `message/message` (the hardening item F3, O20) |
| record gate | the in-repo `sdk/`, required; the stage-3 subset rule retired | 376 files under the gate, 134 of them under `sdk/`; complement empty |
| internal/layering | included, each package by its own row | 14 packages; the 7 SDK rows allow no core SDK import |
| line-ending gate (`TestThePackageSourceIsOneLineEndingThroughout`) | included | 406 files judged against 406 on disk, `sdk/*.go` in both |
| protocol attestation (`TestNothingHereComputesTheAttestationPreimage`) | included | 387 files walked, `sdk/urmessage/pqepoch.go` among the label's files |
| messagegroup retracted sentinel | included | 406 files; 1 line outside the inventory, the paragraph that retracts it |

## 4. Who keeps the non-moved half

| Moving gate | Non-moved half | Kept by |
|---|---|---|
| value census, non-sentinel rulings, Sync rulings, part-size rulings | core package-level values, errors, Syncs and 2048-valued constants | Out of subject: after the sdk removal the core SDK holds no stream adapter, store or message binding for any of them to reach. |
| what upstream added to its copy of the value census after the import (urnetwork/sdk `06f33802`, `ae5a65fc`, `80f6e365`, `69c49348`) | a renamed row (`licenseJSON`), a new row (`mobileMemoryTeardownLifetime`) and a new test, `TestStreamAdapterTeardownConstantsHaveCompleteCensus`, of that constant and `mobileMemoryTeardownCapacity`; then eight more rows and one non-sentinel ruling, for the API client's `ErrNetworkCredentialRequired`, `apiAdminRouteAccess` and `apiAdminRoutePatterns` and for the credential renewer's `closedNetworkRenewerDone` and its four `networkRenewal` timing constants: core values, every one | Out of subject, as the row above, and nothing of it lands here ([ported.tsv](ported.tsv), `port-void`): this package declares none of those values, so it has no row to rename or to add, and the test cannot compile. Its own values (44 named on windows) are still held both ways. The sdk removal's pull request says what holds the two teardown constants once the census has left the core. |
| receive-callback audit | the core provider's control-frame registration | The core's own `device_receive_callback_policy_test.go`, at one entry. |
| test-citation gate | core prose citing core tests (5 names, TestMain at 3 sites) | The core's port, `citation_gate_test.go` (the sdk removal PR). |
| godoc-link gate | none: its subject was URmessage's files only | — |
| pqdarkgate, both walks | core production prose and literals | Out of subject, measured at P_sdk (section 2). |
| record gate's sibling complement | the core SDK's data path | NOT retired (corrected 2026-10-06; this row said "Retired: there is no core code in this tree"). urnetwork/connect 54b5b106 had already put the whole sibling SDK under the gate, with reviewed AST contexts. Ported here (3a22cd99), and the core SDK beside the repository at its pin is a root of the gate (a25b7c8b), scanned whole, every reviewed context held live, required by test.sh (URMESSAGE_REQUIRE_CORE_SDK_ROOT). **O18, the maintainer's call:** keep it (the default) or drop it and record the loss here. |
| test-citation gate, the root module's prose | 4 citations outside the subject that resolve to no single declaration | Printed, and held both ways to `citationOutsideSubjectUnresolved` (3 wrapped across comment lines, 1 message-server test). |
| constant-time importer gate, nested modules | `sdk/urmessage` imports `message/message` outside the root module | Printed, and held both ways to `authNestedImporterDispositions` (F3, ruling O20). |

## 5. The loopback harness under `testdata` (urnetwork/sdk a7b5db77)

Upstream moved the loopback harness from the cgo package's directory to
`cgo/ctest/testdata/loopback_test_world.go`, where `go mod tidy` does not read it, and a build
overlay (`cgo/ctest/loopback-overlay.json`) lays it back into the package for the test library.
The port is `966b77f2`. A directory named `testdata` is what most walks here skip as fixtures, so
the move alone would have taken the harness out of every one of them with no test changing
colour. Each such walk now reads `sdk/cgo/ctest/testdata` by name, and fails if it reads nothing
there; `internal/layering` holds that directory to what the overlay lays down, both ways, and
refuses an overlay nobody declared.

| Walk | Skips `testdata`? | Now |
|---|---|---|
| internal/layering | read for stale literals, judged by no row | a file an overlay lays into a package is judged by that package's row (`sdk/cgo`); `buildOverlays` and `overlaidSourceDirectories`, both ways |
| record gate | yes, unless a root names the directory | the directory is a root of its own (`joinOverlaidSourceRoot`); the complement must not answer the harness as skipped |
| constant-time importer walk | yes | reads `authOverlaidSources`, as the package the overlay lays it into |
| protocol attestation walk | yes | reads the directory, and fails if it walked no file there |
| SDK crypto scope | yes, counted | reads `sdkOverlaidSourceDirs`; the harness's row names it at its new place |
| citation, doc-link and both dark-group walks | yes | `skipsDirectory` reads `overlaidSourceDir`; the doc links resolve against the package the harness is compiled into |
| `sdk/cgo/gen`'s harness test | reads the file by name | reads it at its new place, and exercises the scan's build-constraint guard on it in a directory of its own, as upstream's case does |
| test.sh: gofmt | yes | holds the directory's files, and prints what it does not hold |
| test.sh: the loopback modfile's tidy, the loopback library | — | both pass the overlay; the tidy's control is the same command without it, which must ask to drop the message server |
| line-ending gate, retracted sentinel, receive-callback audit | no | unchanged: they read every directory |

Measured, both ways, on linux (strace over every top-level test of the eight test binaries that
opened the harness, each test run alone, 2,682 before and 2,685 after): the tests whose own
process opens the harness are 19 at `cdd30926`, before the move, and 19 with these changes, 18 of
them the same tests. The one that stopped is `sdk/cgo/gen`'s
`TestTheDefNamesEveryHandWrittenExportThatShips`, whose scan reads the cgo package's directory,
where the harness no longer is; the guard it relied on is the one the harness test now exercises
on purpose. The one that started is `TestLoopbackModuleBoundaryAndOverlay`, which came with the
port.
