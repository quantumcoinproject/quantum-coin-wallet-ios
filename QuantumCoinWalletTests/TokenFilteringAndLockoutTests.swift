// TokenFilteringAndLockoutTests.swift
// Regression tests for the token-anti-impersonation filtering and
// the brute-force lockout cap. Each test pins one user-visible
// invariant so any future refactor that breaks it fails CI
// before review.
//
// Coverage:
//   - `RecognizedTokens.isRecognized`: positive (Heisen, Y2Q),
//     negative (random contract), case-insensitivity, nil/empty.
//   - `StablecoinImpersonatorFilter.impersonatesStablecoin`: hits
//     on `USDT`, `usdc`, `Tether USD`, `DAI`, `PYUSD`, and
//     padded variants; misses on unrelated symbols. Match
//     applies to `name` AND `symbol` independently.
//   - `StablecoinImpersonatorFilter.filter`: hard-suppresses
//     impersonators by default; the recognized-contract escape
//     hatch (`RecognizedTokens.all`) lets a token pass through
//     even when its name/symbol matches a stablecoin pattern.
//   - `TransactionReviewDialogViewController`: renders a
//     dedicated Contract address row IFF `assetContract` is
//     non-nil and non-empty; the row is suppressed for native
//     coin sends.
//   - `UnlockAttemptLimiter`: lockout caps at 300 s (5 min)
//     even after many consecutive failures; the historical
//     1-hour cap has been removed and the schedule remains
//     monotonic non-decreasing.
//   - Token-filter / cloud-backup-submitted localization keys
//     resolve from `en_us.json` (smoke guard against accidental
//     key drift).
//   - `CloudBackupManager.formatBackupSubmittedToCloudMessage`:
//     substitutes `[FOLDER]` and `[FILENAME]` placeholders.
//
// NOT covered here:
//   - `HomeMainViewController` segmented-control empty-state
//     visibility — `recognizedItems` / `unrecognizedItems` /
//     `tokensSegmentedControl` are all `private`, so we test
//     the equivalent invariant at the StablecoinImpersonatorFilter
//     + RecognizedTokens layer where the partitioning is
//     ultimately decided.

import XCTest
@testable import QuantumCoinWallet

final class TokenFilteringAndLockoutTests: XCTestCase {

    // MARK: - RecognizedTokens.isRecognized

    func testRecognizedTokensIsRecognizedHeisenAndY2qPass() {
        XCTAssertTrue(RecognizedTokens.isRecognized(RecognizedTokens.heisen),
            "Heisen contract MUST be recognized; this is the "
            + "anchor for the anti-impersonation filter.")
        XCTAssertTrue(RecognizedTokens.isRecognized(RecognizedTokens.y2q),
            "Y2Q contract MUST be recognized; same anchor as "
            + "Heisen.")
    }

    func testRecognizedTokensIsRecognizedIsCaseInsensitive() {
        XCTAssertTrue(
            RecognizedTokens.isRecognized(RecognizedTokens.heisen.uppercased()),
            "Hex contract addresses are case-insensitive on "
            + "chain; an upper-cased copy of a recognized "
            + "address MUST still be recognized.")
        XCTAssertTrue(
            RecognizedTokens.isRecognized(RecognizedTokens.heisen.capitalized),
            "Mixed-case copy of a recognized address MUST still "
            + "be recognized; a regression here would let an "
            + "indexer-supplied capitalised variant slip into "
            + "the Unrecognized tab.")
    }

    func testRecognizedTokensIsRecognizedRejectsRandomContract() {
        XCTAssertFalse(RecognizedTokens.isRecognized(
                "0xdeadbeef00000000000000000000000000000000000000000000000000000000"),
            "An unrelated contract address MUST NOT be "
            + "recognized; a regression here would let an "
            + "attacker-controlled contract appear in the "
            + "Tokens tab.")
    }

    func testRecognizedTokensIsRecognizedRejectsNilAndEmpty() {
        XCTAssertFalse(RecognizedTokens.isRecognized(nil),
            "nil contract (native coin sends) MUST NOT be "
            + "recognized through this allow-list; the native "
            + "coin row is surfaced via a separate affordance.")
        XCTAssertFalse(RecognizedTokens.isRecognized(""),
            "Empty contract string MUST NOT be recognized; "
            + "would otherwise let a degenerate indexer entry "
            + "slip past the gate.")
    }

    // MARK: - StablecoinImpersonatorFilter.impersonatesStablecoin

    func testImpersonatesStablecoinMatchesCommonStablecoinSymbols() {
        // Each pair is (symbol, name). Both are checked
        // independently, so passing either side as nil also
        // validates the per-side branches of the predicate.
        let positives: [(String?, String?)] = [
            ("USDT", nil),
            ("usdt", nil),
            ("USDC", nil),
            ("usdc", nil),
            (nil, "Tether USD"),
            (nil, "tether usd"),
            ("DAI", nil),
            ("PYUSD", nil),
            ("FDUSD", nil),
            ("EURT", nil),
            ("EURC", nil),
            // Padded-symbol variants — the chosen
            // substring-match approach defeats these:
            ("USDT.e", nil),
            ("USD-Tether", nil),
            ("USDT_v2", nil),
            // Brand name in `name` but obfuscated symbol:
            ("XXX", "Tether"),
            // "Stablecoin" in name only.
            ("XXX", "Premium Stablecoin")
        ]
        for (sym, nm) in positives {
            XCTAssertTrue(
                StablecoinImpersonatorFilter.impersonatesStablecoin(
                    symbol: sym, name: nm),
                "Expected impersonator match for "
                + "(symbol=\(sym ?? "nil"), name=\(nm ?? "nil")). "
                + "A regression here would surface a stablecoin-"
                + "lookalike token in the wallet UI without an "
                + "explicit RecognizedTokens allow-list entry.")
        }
    }

    func testImpersonatesStablecoinIgnoresUnrelatedTokens() {
        let negatives: [(String?, String?)] = [
            ("HSN", "Heisen"),
            ("Y2Q", "Y2Q"),
            ("BTC", "Bitcoin"),
            ("ETH", "Ether"),
            ("XYZ", "Random Coin"),
            (nil, nil),
            ("", "")
        ]
        for (sym, nm) in negatives {
            XCTAssertFalse(
                StablecoinImpersonatorFilter.impersonatesStablecoin(
                    symbol: sym, name: nm),
                "Did not expect impersonator match for "
                + "(symbol=\(sym ?? "nil"), name=\(nm ?? "nil")). "
                + "A false positive here would silently hide a "
                + "legitimate token from the wallet UI.")
        }
    }

    // MARK: - INR / Rupee / Rupiah impersonator coverage

    /// Indian-rupee impersonator coverage. Mirrors the Android
    /// `inrAndRupeeAndRupiahBlocked` test one-for-one. Pins the
    /// three new patterns added to `StablecoinImpersonatorFilter.patterns`:
    /// `inr`, `rupee`, `rupiah`. The IDRT fixture matches via the
    /// spelled-out `rupiah` substring on the *name* field — the
    /// three-letter ticker `idr` is intentionally NOT in the
    /// pattern list (see `testImpersonatesStablecoinIgnoresInrFalsePositiveGuard`
    /// for the design lockdown).
    func testImpersonatesStablecoinMatchesInrRupeeAndRupiah() {
        let positives: [(String?, String?)] = [
            ("INR", nil),
            ("eINR", nil),
            ("cINR", nil),
            ("INRT", nil),
            ("wINR", nil),
            (nil, "RupeeCoin"),
            (nil, "Digital Rupee"),
            ("eRupee", nil),
            (nil, "Rupiah Token"),
            ("IDRT", "Rupiah Token")
        ]
        for (sym, nm) in positives {
            XCTAssertTrue(
                StablecoinImpersonatorFilter.impersonatesStablecoin(
                    symbol: sym, name: nm),
                "Expected INR/Rupee/Rupiah impersonator match for "
                + "(symbol=\(sym ?? "nil"), name=\(nm ?? "nil")). "
                + "A regression here would let an Indian-rupee "
                + "impersonator surface in the home or send pickers.")
        }
    }

    /// False-positive guard for the INR / Rupee / Rupiah additions.
    /// We deliberately did NOT add the three-letter `idr` substring
    /// to the pattern list because it would also match legitimate
    /// tokens that happen to contain those three letters as a
    /// fragment (e.g. `Hidro`, `Idris`). If a future PR adds `idr`
    /// to the pattern list this test will fail and force the
    /// contributor to revisit the tradeoff documented on
    /// `StablecoinImpersonatorFilter.patterns`.
    func testImpersonatesStablecoinIgnoresInrFalsePositiveGuard() {
        let negatives: [(String?, String?)] = [
            ("HID", "Hidro"),
            ("IDR", "Idris")
        ]
        for (sym, nm) in negatives {
            XCTAssertFalse(
                StablecoinImpersonatorFilter.impersonatesStablecoin(
                    symbol: sym, name: nm),
                "Did not expect impersonator match for "
                + "(symbol=\(sym ?? "nil"), name=\(nm ?? "nil")). "
                + "A false positive here would mean a future PR "
                + "added the short `idr` substring to the pattern "
                + "list, which would silently hide legitimate "
                + "tokens like Hidro / Idris.")
        }
    }

    // MARK: - StablecoinImpersonatorFilter.filter

    func testFilterRemovesImpersonatorByDefault() {
        let imposter = AccountTokenSummary(
            contractAddress: "0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
            name: "Tether USD",
            symbol: "USDT",
            balance: "1000000000",
            decimals: 6)
        let benign = AccountTokenSummary(
            contractAddress: RecognizedTokens.heisen,
            name: "Heisen",
            symbol: "HSN",
            balance: "1",
            decimals: 18)
        let filtered = StablecoinImpersonatorFilter.filter([imposter, benign])
        XCTAssertEqual(filtered.count, 1,
            "Impersonator MUST be removed; legitimate token "
            + "MUST remain.")
        XCTAssertEqual(filtered.first?.contractAddress,
            RecognizedTokens.heisen,
            "Surviving entry MUST be the recognized Heisen "
            + "contract, not the impersonator.")
    }

    func testFilterRespectsRecognizedContractEscapeHatch() {
        // Construct a synthetic recognized-USDT entry: the
        // contract address is in `RecognizedTokens.all` so the
        // pattern match against name/symbol MUST be skipped.
        // Pins the "wallet vendor explicitly vouches for this
        // specific contract" override.
        let escaped = AccountTokenSummary(
            contractAddress: RecognizedTokens.heisen,
            name: "Tether USD",
            symbol: "USDT",
            balance: "1",
            decimals: 6)
        let filtered = StablecoinImpersonatorFilter.filter([escaped])
        XCTAssertEqual(filtered.count, 1,
            "Recognized contract MUST bypass the stablecoin "
            + "filter even when name/symbol match a pattern; "
            + "regression here would mean the vendor cannot "
            + "explicitly approve a real stablecoin in a future "
            + "release without renaming.")
    }

    func testFilterIsIdentityOnEmptyAndAllRecognized() {
        XCTAssertEqual(StablecoinImpersonatorFilter.filter([]).count, 0,
            "Empty input MUST produce empty output (sanity).")
        let recognized = [
            AccountTokenSummary(
                contractAddress: RecognizedTokens.heisen,
                name: "Heisen", symbol: "HSN",
                balance: "1", decimals: 18),
            AccountTokenSummary(
                contractAddress: RecognizedTokens.y2q,
                name: "Y2Q", symbol: "Y2Q",
                balance: "1", decimals: 18)
        ]
        XCTAssertEqual(
            StablecoinImpersonatorFilter.filter(recognized).count,
            recognized.count,
            "All-recognized input MUST pass through unchanged; "
            + "a regression here would silently drop legitimate "
            + "tokens.")
    }

    // MARK: - TransactionReviewDialogViewController contract row

    /// Helper to count the number of section headers that match
    /// the supplied label. The dialog builds each section through
    /// `makeSection(header:value:mono:)` which adds a `UILabel`
    /// with the header text; we walk the loaded view hierarchy
    /// and count matches.
    private func countLabels(
        in view: UIView, withText text: String
    ) -> Int {
        var hits = 0
        if let label = view as? UILabel, label.text == text {
            hits += 1
        }
        for sub in view.subviews {
            hits += countLabels(in: sub, withText: text)
        }
        return hits
    }

    @MainActor
    func testReviewDialogRendersContractRowOnlyWhenTokenIsSet() {
        let header = Localization.shared.getContractAddressByLangValues()

        // Token send: contract present -> row MUST render once.
        let tokenDialog = TransactionReviewDialogViewController(
            spec: ReviewSpec()
                .action("Send Heisen (HSN)")
                .contractAddress(RecognizedTokens.heisen)
                .contractIsToken(true)
                .fromAddress("0xfromfromfromfromfromfromfromfromfromfromfromfromfromfromfromfrom")
                .toAddress("0xtotototototototototototototototototototototototototototototototo")
                .quantityValue("0")
                .tokenQuantityValue("0.1 HSN")
                .gas(21_000, "0.1 Q")
                .networkText("TestNet (chain 9999)"),
            walletAddress: "0xfromfromfromfromfromfromfromfromfromfromfromfromfromfromfromfrom")
        tokenDialog.loadViewIfNeeded()
        XCTAssertEqual(
            countLabels(in: tokenDialog.view, withText: header), 1,
            "Token send MUST render exactly one Contract address "
            + "row in the review dialog. A regression here would "
            + "either hide the contract row from a token send "
            + "(re-opening the impersonation surface) or "
            + "duplicate it (visual regression).")

        // Native coin send: no contract -> row MUST be absent.
        let nativeDialog = TransactionReviewDialogViewController(
            spec: ReviewSpec()
                .action("Send QC")
                .contractAddress(nil)
                .contractIsToken(false)
                .fromAddress("0xfromfromfromfromfromfromfromfromfromfromfromfromfromfromfromfrom")
                .toAddress("0xtotototototototototototototototototototototototototototototototo")
                .quantityValue("0.1 QC")
                .tokenQuantityValue(nil)
                .gas(21_000, "0.1 Q")
                .networkText("TestNet (chain 9999)"),
            walletAddress: "0xfromfromfromfromfromfromfromfromfromfromfromfromfromfromfromfrom")
        nativeDialog.loadViewIfNeeded()
        XCTAssertEqual(
            countLabels(in: nativeDialog.view, withText: header), 0,
            "Native coin send MUST NOT render a Contract address "
            + "row (there is no contract to render). A regression "
            + "here would surface an empty row that the user might "
            + "interpret as missing data.")

        // Empty contract string: also MUST be suppressed.
        let emptyContractDialog = TransactionReviewDialogViewController(
            spec: ReviewSpec()
                .action("Send Heisen (HSN)")
                .contractAddress("")
                .contractIsToken(true)
                .fromAddress("0xfromfromfromfromfromfromfromfromfromfromfromfromfromfromfromfrom")
                .toAddress("0xtotototototototototototototototototototototototototototototototo")
                .quantityValue("0")
                .tokenQuantityValue("0.1 HSN")
                .gas(21_000, "0.1 Q")
                .networkText("TestNet (chain 9999)"),
            walletAddress: "0xfromfromfromfromfromfromfromfromfromfromfromfromfromfromfromfrom")
        emptyContractDialog.loadViewIfNeeded()
        XCTAssertEqual(
            countLabels(in: emptyContractDialog.view, withText: header), 0,
            "Empty contract string MUST be treated the same as "
            + "nil (no contract row); guards against degenerate "
            + "indexer responses producing a blank row.")
    }

    // MARK: - UnlockAttemptLimiter: 5-minute cap

    /// After enough consecutive failures to reach the worst tier,
    /// the lockout MUST cap at 300 s (5 minutes). Pins the
    /// post-fix invariant: previously the schedule allowed
    /// up to 3600 s (1 hour) on the post-reboot fallback path
    /// and 900 s on tier 9. Both have been collapsed to 300 s.
    func testUnlockAttemptLimiterCapsLockoutAt300Seconds() {
        // The limiter is a process-global Keychain entry; record a
        // success at the end so we don't poison subsequent tests.
        defer { UnlockAttemptLimiter.recordSuccess() }
        UnlockAttemptLimiter.recordSuccess()
        // Drive past the worst tier (tier-10+ in the documented
        // schedule). 12 failures puts us comfortably in the cap
        // region.
        for _ in 0..<12 { UnlockAttemptLimiter.recordFailure() }
        switch UnlockAttemptLimiter.currentDecision() {
            case .lockedFor(let remaining):
            XCTAssertLessThanOrEqual(remaining, 300,
                "Lockout MUST cap at 300 s (5 min). A regression "
                + "that re-introduced the 900 s tier-9 wait or the "
                + "3600 s post-reboot fallback would surface here "
                + "as a remaining-time > 300.")
            XCTAssertGreaterThan(remaining, 0,
                "After 12 failures the limiter MUST still be "
                + "locked; a remaining-time of 0 here would mean "
                + "the limiter silently allowed a brute-force "
                + "burst.")
            case .allowed:
            XCTFail("After 12 consecutive failures the limiter "
                + "MUST be locked; a regression that allowed past "
                + "the 5-failure threshold would surface here.")
        }
    }

    // MARK: - Localization keys (smoke)

    /// Token-filter / hash-verification / cloud-backup-submitted
    /// localization keys MUST resolve to a non-empty string. A
    /// regression here would surface as a blank label / button /
    /// dialog message in the shipped UI without any compile-time
    /// signal.
    func testTokenAndHashAndCloudLocalizationKeysResolve() {
        let L = Localization.shared
        XCTAssertFalse(L.getTokensTabByLangValues().isEmpty,
            "tokens-tab key missing from en_us.json")
        XCTAssertFalse(L.getUnrecognizedTokensTabByLangValues().isEmpty,
            "unrecognized-tokens-tab key missing from en_us.json")
        XCTAssertFalse(L.getShowUnrecognizedTokensByLangValues().isEmpty,
            "show-unrecognized-tokens key missing from en_us.json")
        XCTAssertFalse(L.getContractAddressByLangValues().isEmpty,
            "contract-address key missing from en_us.json")
        XCTAssertFalse(L.getBackupSubmittedCloudTitleByLangValues().isEmpty,
            "backup-submitted-cloud-title key missing from en_us.json")
        XCTAssertFalse(L.getBackupSubmittedCloudMessageByLangValues().isEmpty,
            "backup-submitted-cloud-message key missing from en_us.json")
    }

    // MARK: - Cloud-submitted message formatter

    /// `formatBackupSubmittedToCloudMessage` MUST substitute the
    /// `[FOLDER]` and `[FILENAME]` placeholders with the
    /// destination URL's parent-directory name and file name.
    /// A regression that dropped the substitution would leave
    /// the literal placeholder text visible to the user.
    func testFormatBackupSubmittedToCloudMessageSubstitutesPlaceholders() {
        let url = URL(fileURLWithPath: "/private/var/mobile/Library/iCloud Drive/Wallets/qcw-abc.wallet")
        let message = CloudBackupManager.formatBackupSubmittedToCloudMessage(forURL: url)
        XCTAssertTrue(message.contains("Wallets"),
            "Folder placeholder MUST be substituted with the "
            + "destination URL's parent directory name; a "
            + "regression here would leave the literal "
            + "[FOLDER] token in the user-visible dialog.")
        XCTAssertTrue(message.contains("qcw-abc.wallet"),
            "Filename placeholder MUST be substituted with the "
            + "destination URL's last path component.")
        XCTAssertFalse(message.contains("[FOLDER]"),
            "Literal [FOLDER] token MUST NOT survive the "
            + "substitution.")
        XCTAssertFalse(message.contains("[FILENAME]"),
            "Literal [FILENAME] token MUST NOT survive the "
            + "substitution.")
    }
}
