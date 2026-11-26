package rules

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Custom rules let a team add its own patterns to the scan: an internal host
// that must never appear in a vendor's description, a product name a
// competitor's tool should not claim, a phrase their red team found. They run
// beside the built-in rules, with the same negation window and the same
// first-hit semantics, and they are carried as plain specs wherever a result
// has to be recomputed later (an evidence pack), so a grade made with a
// custom rule can still be checked by someone who never saw the service.
//
// Go's regexp is RE2: matching is linear in the input, so a customer's
// pattern cannot be turned into a denial of service by catastrophic
// backtracking. Length is capped anyway.

// Spec is a custom rule as written by a person and as stored.
type Spec struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Note    string `json:"note"`
	Tier    string `json:"tier"` // review | info
}

var customID = regexp.MustCompile(`^C-[A-Z0-9][A-Z0-9-]{0,39}$`)

const maxPattern = 500

// Validate says what is wrong with a spec, in words a person can act on.
func (s Spec) Validate() error {
	if !customID.MatchString(s.ID) {
		return errors.New("a custom rule id is C- followed by capitals, digits or dashes, e.g. C-INTERNAL-HOST")
	}
	for _, r := range Rules {
		if r.ID == s.ID {
			return errors.New("that id is a built-in rule")
		}
	}
	if s.Tier != "review" && s.Tier != "info" {
		return errors.New("tier is review or info")
	}
	if strings.TrimSpace(s.Pattern) == "" || len(s.Pattern) > maxPattern {
		return fmt.Errorf("the pattern is 1 to %d characters", maxPattern)
	}
	if _, err := regexp.Compile(s.Pattern); err != nil {
		return fmt.Errorf("the pattern does not compile: %v", err)
	}
	if len(s.Note) > 200 {
		return errors.New("the note is at most 200 characters")
	}
	return nil
}

// Compile turns specs into rules. Every spec must validate.
func Compile(specs []Spec) ([]Rule, error) {
	out := make([]Rule, 0, len(specs))
	for _, s := range specs {
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.ID, err)
		}
		note := s.Note
		if note == "" {
			note = "custom rule"
		}
		// The tier rides in the category ("custom:review"), so built-in rule
		// literals keep their four fields.
		out = append(out, Rule{ID: s.ID, Category: "custom:" + s.Tier, Re: regexp.MustCompile(s.Pattern), Note: note})
	}
	return out, nil
}

// IsReview says whether a hit of id belongs to the review tier, for built-in
// and custom rules alike.
func IsReview(id string, extra []Rule) bool {
	if Review[id] {
		return true
	}
	for _, r := range extra {
		if r.ID == id {
			return r.Category == "custom:review"
		}
	}
	return false
}

// NoteOf is the human description of a rule, built-in or custom.
func NoteOf(id string, extra []Rule) string {
	if n, ok := Notes()[id]; ok {
		return n
	}
	for _, r := range extra {
		if r.ID == id {
			return r.Note
		}
	}
	return id
}
