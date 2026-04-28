//
// BIP39Words.swift
//
// Mirror of `GlobalMethods.ALL_SEED_WORDS` / `SEED_WORD_SET`. Populated
// once on app launch via `Bootstrap.loadSeedsThreadEquivalent`.
//
// Android reference:
//   app/src/main/java/com/quantumcoinwallet/app/utils/GlobalMethods.java
//

import Foundation

@MainActor
public enum BIP39Words {

    public private(set) static var all: [String] = []
    public private(set) static var set: Set<String> = []

    public static func setAll(_ words: [String]) {
        all = words
        set = Set(words)
    }

    public static func exists(_ word: String) -> Bool {
        set.contains(word.lowercased())
    }

    public static func suggestions(prefix: String, limit: Int = 10) -> [String] {
        guard prefix.count >= 2 else { return [] }
        let lower = prefix.lowercased()
        var hits: [String] = []
        for w in all where w.hasPrefix(lower) {
            hits.append(w)
            if hits.count >= limit { break }
        }
        return hits
    }
}
