# Stage 2a: what the move could narrow, and what was measured

The foundational packages kept every relative path between them (mls still reaches
`../message` and `../messagegroup`), with one exception: the codec moved from beneath mls
(`connect/mls/syntax`) to a peer (`syntax`). Every scope that reached the codec by recursion
under mls lost it in silence unless it was rewritten to name it. This file records, for every
such scope, what it read in connect at e449f7d8 and what it reads here, measured with the
gates' own helpers.

## 1. Every scan of mls's sources

`mls/scan_scope_test.go` holds the scope ARGUMENT of every call of `mustScanSources` and
`scanSources` in package mls. Each call is handed `urmessageScanRoots()` (the cryptographic
roots plus the codec), the control fixture, or a narrower root declared with its reason:

| Calls | Scope | Where |
|---|---|---|
| 16 | `urmessageScanRoots()` | crypto_forbidden 7 (TestForbiddenPrimitivesAreAbsent, TestHkdfExtractHasOnlyTwoCallSites, TestEcdhHasOneCallSite, TestEcdhResultIsNeverDiscarded, TestScanRefusesARootItCannotCover, TestForbiddenScanCoversEveryRoot, TestForbiddenScanSkipsTheControlFixture); crypto_test 2 (declarationsOfEveryScannedPackage, TestNoStubShapesRemainInSource); framing_group_seams 5; group_test 1; staged_erase 1 (eraseReadingOf) |
| 4 | `[]string{forbiddenControlRoot}` | the control fixtures |
| 3 | declared narrower | `mustScanSources:roots` (the helper itself), `TestScanRefusesARootItCannotCover:roots` (the refusal table), `theContentTypeConstants:[]string{"."}` (mls's own ContentType constants; the codec declares none) |

The two counting checks over those scans (TestForbiddenScanCoversEveryRoot and the gates
index walk, `gatesTestSources`) count `urmessageScanRoots()` too.

## 2. Every other reference to `forbiddenScanRoots`

These read package directories, not trees: `typeCheckedBodiesOf` and `rootSourcePaths` glob
`<root>/*.go`, `packageLevelDeclarations` and `declaredFunctionsOf` read one directory, and
`cryptoSourcePaths` globs one directory. In connect they read the three packages mls, message
and messagegroup, never mls/syntax (a subdirectory), and they read the same three here. The
package file sets are equal: mls 46 production files (142 with tests in connect, 143 here, the
one more being the new scan_scope_test.go), message 7 (16), messagegroup 20 (60).

| Reference (function) | What it reads per root | Disposition |
|---|---|---|
| TestTheScanRootsAreEveryCryptographicPackageConnectedToThisOne | the list itself, against the derived class | unchanged; codecScanRoots gets the same both-ways equality |
| TestHkdfExtractHasOnlyTwoCallSites (message text) | names the list in its failure | unchanged |
| declarationsOfEveryScannedPackage | groups the urmessageScanRoots() scan by directory, then requires each of the three roots to contribute | unchanged; the grouping now holds syntax/ as connect's held mls/syntax |
| TestTheExcuseReaderJudgesASeamAtEveryRootTheGuardrailsWalk | the three package directories | unchanged, equal sets |
| TestTheTypeCheckedWalkReadsTheSameSourceAsTheParseTreeWalk | membership of cryptoOwnRoot in the list | unchanged |
| TestNoEntropyTakingFunctionLivesWhereThisGateCannotCallIt | `packageLevelDeclarations`, `declaredFunctionsOf` of message and messagegroup | unchanged, equal sets |
| cryptoSourcePaths | `<root>/*.go`, production | unchanged, equal sets (its comment already excluded the codec as another plan's package) |
| epochMoverRoots (epoch_advance_test.go), TestEveryDeclarationThatMovesAGroupToAnotherEpochEndsTheProposalCacheBinding | `typeCheckedBodiesOf` per root, and the alias equality | unchanged, equal sets |
| extensionTypeSelectionRoots (extension_lookup_test.go) | `typeCheckedBodiesOf` per root | unchanged, equal sets |
| TestEveryConstructionBypassSeamIsDeclaredInTestSource | requires each of the three roots to contribute to its urmessageScanRoots() scan | unchanged |
| TestFramingUsesConstantTimeComparison | `typeCheckedBodiesOf` and `rootSourcePaths` per root | unchanged, equal sets |
| TestNoPackageBeneathTheseRootsComparesAWholeOctetStringWithGoEquality | `productionPackagesBeneath`, which DOES recurse: in connect it found mls/syntax beneath "." | changed: codecScanRoots is appended by name (commit "mls: scan the promoted codec by name") |
| lineEndingScanRoots (vectors_runner_test.go) | requires the module walk to reach each root | unchanged; see section 4, (v) |

## 3. The other module walks

| Walk | Root in connect | Root here | Disposition |
|---|---|---|---|
| message/writeauth_test.go TestEveryPackageBuiltOnThisOneIsUnderTheConstantTimeGate | the connect module | this repository's root module | Same subject (production importers of the record package): messagegroup in both. Measured in connect: 0 production importers of connect/message outside the moved directories (control: the same grep finds 6 files inside them, in messagegroup and message/testdata/forbidden). |
| messagegroup/ephkey_test.go TestTheRetractedSentinelSurvivesOnlyInTheParagraphThatRetractsIt | the connect module | this repository's root module | Same answer: measured in connect, the sentinel occurs in 0 files outside the moved directories (control: 2 files inside them). |
| message/record_test.go joinScanRoots | the three record roots + the codec by recursion + ../sdk if present | the same roots + syntaxRoot + ../sdk if present, by the stage-3 rule | See section 4, (iii), and commit "message: the record gate reads the codec by name". |
| mls/vectors_runner_test.go TestThePackageSourceIsOneLineEndingThroughout | every .go under the connect module | every .go under this repository | See section 4, (v). |

## 4. Scope diff (plan section 5.4f)

Measured by scope_diff.py with each gate's own helper, in a connect e449f7d8 export and in
this branch at 5dd976d7 (the commit before this one), and compared modulo
`mls/syntax -> syntax`. "Equal" lets this side hold the files this branch declares new, and
nothing else. Result: PASS.

| | connect e449f7d8 | here | Difference |
|---|---|---|---|
| (i) cross-platform patterns | `./mls/... ./message/... ./messagegroup/...` -> message, messagegroup, mls, mls/syntax | `./...` -> internal/layering, internal/repository, message, messagegroup, mls, syntax | none lost; the two test-only internal packages added |
| (i) the codec workflow's pattern | `./mls/syntax/...` -> mls/syntax | `./syntax/...` -> syntax | equal |
| (ii) the recursive scans | 243 files | 244 files | + mls/scan_scope_test.go (declared new) |
| (iii) the record gate's roots (no sdk sibling) | 243 files | 244 files | + mls/scan_scope_test.go (declared new) |
| (iv) the crypto derivation | class message, messagegroup, mls; mls/syntax connected and not cryptographic | class message, messagegroup, mls; syntax connected and not cryptographic | equal |
| (v) the line-ending gate's files | 1616, of which 258 in the moved directories | 261 | + internal/layering, internal/repository and mls/scan_scope_test.go (declared new) |

The controls, each run on a copy and reverted:
- the connect cross-platform patterns put back: FAIL, "(i) the cross-platform patterns lost
  ['syntax']" (the omission plan v1's prototype had);
- urmessageScanRoots() without the codec, and the record roots without syntaxRoot: FAIL,
  (ii) and (iii) each lose the 23 syntax files.

## 5. Who keeps the non-moved half

A gate whose walk root is a module root reads files that do not move. Each such gate has a
row here before its file moves:

| Moving gate | Non-moved half (in connect) | Kept by |
|---|---|---|
| mls/vectors_runner_test.go TestThePackageSourceIsOneLineEndingThroughout | connect's other 1,358 .go files | a connect-local line-ending gate, in the connect removal PR (the maintainer's call; if declined, the coverage loss is recorded there) |
| message/writeauth_test.go importer gate | none: 0 production importers outside the moved directories | out of subject once connect drops the record package |
| messagegroup/ephkey_test.go retracted sentinel | none: 0 files outside the moved directories | out of subject once connect drops messagegroup |
| message/record_test.go sdk root | the core SDK's VPN data path | SUPERSEDED (2026-10-06). This row said "out of subject", and upstream decided otherwise the day before: urnetwork/connect 54b5b106 (Bitprecipice, 2026-10-05) keeps the WHOLE sibling SDK under the gate, with six TCP/IP and pool-accounting operations reviewed by their complete AST. This repository ports that commit (3a22cd99) and scans the core SDK checked out beside it again (a25b7c8b), required by test.sh. **O18, the maintainer's call:** keep this coverage here, as the stronger default, or drop it and record the loss in this row. |
| mls/syntax/layering_test.go workflow tests (TestSyntaxWorkflowRunsEveryFuzzTarget, TestSyntaxWorkflowGatesRatherThanReports, and this repository's structural version of them) | none: they read the codec's own workflow | Removed upstream with GitHub Actions (urnetwork/connect e8611390) and here by its port (4be82ed6). The fuzz legs they held run in test.sh, 60 s per target, the targets derived from the source; the module census requires the root module's "fuzz" receipt, so a deleted leg is a census failure. |
| connect layering_test.go | connect's own root package | stays in connect (TestConnectDoesNotImportItsOwnSubpackages); its TestSubpackagesDoNotImportBack rows are internal/layering's rows here |
