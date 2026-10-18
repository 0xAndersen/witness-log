package witnesslog

import (
	"strings"
	"unicode"
)

// normalizeLabel is the reference's normalize_label, exactly: split on
// Unicode White_Space runs (dropping leading and trailing ones), join with
// one space, then Unicode full default lowercasing (Rust's
// str::to_lowercase). Operator, compute-provider and subject_org labels
// all go through it, so an operator cannot inflate diversity with case or
// spacing variants, and the three verifiers bucket the same labels the
// same way (spec/SPEC.md §7, security review of 0.5.0, F12).
//
// strings.Fields splits on unicode.IsSpace, which is White_Space (U+0085
// included, U+FEFF not), as Rust's split_whitespace does.
func normalizeLabel(s string) string {
	return lowerFull(strings.Join(strings.Fields(s), " "))
}

// Code points lowerFull treats specially.
const (
	capitalIWithDotAbove = 0x0130 // lowercases to "i" + U+0307
	combiningDotAbove    = 0x0307
	capitalSigma         = 0x03a3
	finalSmallSigma      = 0x03c2
	smallSigma           = 0x03c3
)

// lowerFull is Unicode full default lowercasing: unicode.ToLower per rune,
// plus the two locale-independent mappings of SpecialCasing.txt that differ
// from the simple mapping strings.ToLower applies: U+0130 becomes "i"
// followed by U+0307, and U+03A3 (capital sigma) becomes final sigma
// (U+03C2) under the Final_Sigma condition, U+03C3 otherwise.
func lowerFull(s string) string {
	if !strings.ContainsRune(s, capitalIWithDotAbove) && !strings.ContainsRune(s, capitalSigma) {
		return strings.ToLower(s)
	}
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		switch r {
		case capitalIWithDotAbove:
			b.WriteByte('i')
			b.WriteRune(combiningDotAbove)
		case capitalSigma:
			if finalSigma(runes, i) {
				b.WriteRune(finalSmallSigma)
			} else {
				b.WriteRune(smallSigma)
			}
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// finalSigma is the Final_Sigma condition (Unicode §3.13, Table 3-17) as
// the reference evaluates it: skipping case-ignorable characters, the
// nearest character before position i is cased, and the nearest one after
// it is not (or there is none).
func finalSigma(runes []rune, i int) bool {
	before := false
	for j := i - 1; j >= 0; j-- {
		if !caseIgnorable(runes[j]) {
			before = cased(runes[j])
			break
		}
	}
	if !before {
		return false
	}
	for j := i + 1; j < len(runes); j++ {
		if !caseIgnorable(runes[j]) {
			return !cased(runes[j])
		}
	}
	return true
}

// cased is the Cased property: Lowercase, Uppercase or Lt.
func cased(r rune) bool {
	return unicode.In(r, unicode.Ll, unicode.Lu, unicode.Lt, unicode.Other_Lowercase, unicode.Other_Uppercase)
}

// caseIgnorable is the Case_Ignorable property: Word_Break MidLetter,
// MidNumLet or Single_Quote, or General_Category Mn, Me, Cf, Lm or Sk.
func caseIgnorable(r rune) bool {
	switch r {
	case 0x0027: // Single_Quote
		return true
	case 0x002e, 0x2018, 0x2019, 0x2024, 0xfe52, 0xff07, 0xff0e: // MidNumLet
		return true
	case 0x003a, 0x00b7, 0x0387, 0x055f, 0x05f4, 0x2027, 0xfe13, 0xfe55, 0xff1a: // MidLetter
		return true
	}
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk)
}
