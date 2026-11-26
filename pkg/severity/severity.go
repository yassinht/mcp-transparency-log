// Package severity grades a change in a tool surface: not whether the server
// changed, which the hash already says, but whether the change is the kind a
// reviewer must read before an agent is allowed to see it.
//
// Every grade is the result of a rule a reader can re-run on the two texts;
// there is no model and no score, only reasons. The grades are deliberately
// few:
//
//	none    nothing a model reads changed (whitespace, key order)
//	info    capability shrank or cosmetic text moved: a tool removed, a title edited
//	review  a model-facing text or schema changed and a human should read it
//	high    the new text carries a pattern the rule scan flags for review, an
//	        annotation flipped towards more power, or a link now leaves the host
//
// "high" is still not "malicious". It means: read this first.
package severity

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/yassinht/mcp-transparency-log/pkg/evidence"
	"github.com/yassinht/mcp-transparency-log/pkg/rules"
)

type Level string

const (
	None   Level = "none"
	Info   Level = "info"
	Review Level = "review"
	High   Level = "high"
)

var rank = map[Level]int{None: 0, Info: 1, Review: 2, High: 3}

// Reason is one finding that contributed to the grade, with the tool it
// concerns and the level it argues for on its own.
type Reason struct {
	Level  Level  `json:"level"`
	Tool   string `json:"tool,omitempty"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Verdict is the grade and every reason behind it, worst first.
type Verdict struct {
	Level   Level    `json:"level"`
	Reasons []Reason `json:"reasons"`
}

// Classify grades the step from before to after. host is the server's own
// host, used to tell an off-host link from documentation of the server itself.
func Classify(before, after []json.RawMessage, host string) Verdict {
	return ClassifyWith(before, after, host, nil)
}

// ClassifyWith grades with extra (custom) rules beside the built-in ones. A
// new hit of a custom review-tier rule grades high, like a built-in one.
func ClassifyWith(before, after []json.RawMessage, host string, extra []rules.Rule) Verdict {
	added, removed, edited := evidence.DiffTools(before, after)
	v := Verdict{Level: None, Reasons: []Reason{}}
	add := func(l Level, tool, code, detail string) {
		v.Reasons = append(v.Reasons, Reason{Level: l, Tool: tool, Code: code, Detail: detail})
		if rank[l] > rank[v.Level] {
			v.Level = l
		}
	}

	bt, at := byName(before), byName(after)
	beforeHits := rules.HitsWith(bt, host, extra)
	afterHits := rules.HitsWith(at, host, extra)

	// 1. Model-directed text that was not there before, anywhere in the surface.
	for id, h := range afterHits {
		if _, had := beforeHits[id]; had {
			continue
		}
		if rules.IsReview(id, extra) {
			add(High, h.Tool, "new-"+strings.ToLower(id), fmt.Sprintf("new text matches %s (%s) in %s: %q", id, rules.NoteOf(id, extra), h.Field, h.Snippet))
		} else if id == rules.URLExt {
			add(High, h.Tool, "new-off-host-link", "a link now points off the server's host: "+h.Snippet)
		} else {
			add(Review, h.Tool, "new-"+strings.ToLower(id), fmt.Sprintf("new text matches %s (%s) in %s", id, rules.NoteOf(id, extra), h.Field))
		}
	}

	// 2. Tools that appeared: new capability the reviewer never saw.
	for _, name := range added {
		add(Review, name, "tool-added", "a tool the reviewer has not seen before")
	}
	// 3. Tools that vanished: a loss, worth knowing, rarely dangerous.
	for _, name := range removed {
		add(Info, name, "tool-removed", "the tool is no longer served")
	}

	// 4. Edits under the same name.
	for _, e := range edited {
		ob, nb := bt[e.Tool], at[e.Tool]
		for _, f := range e.Fields {
			switch f {
			case "description":
				if strings.Join(strings.Fields(e.DescriptionBefore), " ") == strings.Join(strings.Fields(e.DescriptionAfter), " ") {
					add(None, e.Tool, "description-whitespace", "only whitespace changed")
				} else {
					add(Review, e.Tool, "description-edited", "the description the model reads was rewritten in place")
				}
			case "inputSchema":
				schemaFindings(e.Tool, ob, nb, add)
			case "annotations":
				annotationFindings(e.Tool, ob, nb, add)
			case "title":
				add(Info, e.Tool, "title-edited", "the human-facing title changed")
			case "outputSchema":
				add(Review, e.Tool, "output-schema-edited", "the declared output shape changed")
			default:
				add(Info, e.Tool, "member-edited", "member "+f+" changed")
			}
		}
	}
	sort.SliceStable(v.Reasons, func(i, j int) bool { return rank[v.Reasons[i].Level] > rank[v.Reasons[j].Level] })
	return v
}

// schemaFindings reads what changed in an input schema: new properties, new
// required parameters, loosened types. A new required parameter is a review
// item because the agent will now be asked to supply something it was not
// supplying before, which is how exfiltration via parameters begins.
func schemaFindings(tool string, before, after json.RawMessage, add func(Level, string, string, string)) {
	ob, oa := schemaOf(before), schemaOf(after)
	if ob == nil || oa == nil {
		add(Review, tool, "schema-edited", "the input schema changed")
		return
	}
	bp, ap := props(ob), props(oa)
	var newProps []string
	for k := range ap {
		if _, had := bp[k]; !had {
			newProps = append(newProps, k)
		}
	}
	sort.Strings(newProps)
	br, ar := required(ob), required(oa)
	var newReq []string
	for k := range ar {
		if !br[k] {
			newReq = append(newReq, k)
		}
	}
	sort.Strings(newReq)
	switch {
	case len(newReq) > 0:
		add(Review, tool, "new-required-parameter", "parameters now required: "+strings.Join(newReq, ", "))
	case len(newProps) > 0:
		add(Review, tool, "new-parameter", "new parameters: "+strings.Join(newProps, ", "))
	}
	// Parameter descriptions are text the model reads; an in-place edit there
	// is a description edit.
	changedDesc := 0
	for k, nv := range ap {
		if ov, had := bp[k]; had && descOf(ov) != descOf(nv) {
			changedDesc++
		}
	}
	if changedDesc > 0 {
		add(Review, tool, "parameter-description-edited", fmt.Sprintf("%d parameter description(s) rewritten in place", changedDesc))
	}
	if len(newReq) == 0 && len(newProps) == 0 && changedDesc == 0 {
		add(Info, tool, "schema-edited", "the input schema changed in a way that adds no parameter (types, enums or order)")
	}
}

// annotationFindings catches hints flipping towards more power. Clients and
// models use these to decide whether to ask the user first; a tool that was
// read-only yesterday and is not today deserves the question again.
func annotationFindings(tool string, before, after json.RawMessage, add func(Level, string, string, string)) {
	ob, oa := annotationsOf(before), annotationsOf(after)
	// An absent hint has the default the specification gives it, and the
	// defaults lean unsafe on purpose: a client that does not know assumes
	// the tool may destroy and may reach the open world.
	defaults := map[string]bool{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true}
	effective := func(m map[string]bool, key string) bool {
		if v, ok := m[key]; ok {
			return v
		}
		return defaults[key]
	}
	flip := func(key string, safeValue bool, msg string) {
		if effective(ob, key) == safeValue && effective(oa, key) != safeValue {
			add(High, tool, "annotation-"+key, msg)
		}
	}
	flip("readOnlyHint", true, "readOnlyHint was true and is no longer: the tool now declares it may write")
	flip("destructiveHint", false, "destructiveHint was false and is no longer: the tool now declares destructive effects")
	flip("openWorldHint", false, "openWorldHint was false and is no longer: the tool now declares it reaches outside its own system")
	flip("idempotentHint", true, "idempotentHint was true and is no longer")
	if len(ob) == len(oa) {
		same := true
		for k, b := range ob {
			if a, ok := oa[k]; !ok || a != b {
				same = false
			}
		}
		if same {
			add(Info, tool, "annotations-edited", "annotations changed only in members that are not hints")
			return
		}
	}
	add(Info, tool, "annotations-edited", "annotations changed")
}

// ---------------------------------------------------------------- helpers

func byName(tools []json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, t := range tools {
		var nm struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(t, &nm) == nil && nm.Name != "" {
			if _, dup := out[nm.Name]; !dup {
				out[nm.Name] = t
			}
		}
	}
	return out
}

func schemaOf(t json.RawMessage) map[string]any {
	var x struct {
		InputSchema map[string]any `json:"inputSchema"`
	}
	if json.Unmarshal(t, &x) != nil {
		return nil
	}
	return x.InputSchema
}

func props(s map[string]any) map[string]any {
	p, _ := s["properties"].(map[string]any)
	return p
}

func required(s map[string]any) map[string]bool {
	out := map[string]bool{}
	if arr, ok := s["required"].([]any); ok {
		for _, v := range arr {
			if str, ok := v.(string); ok {
				out[str] = true
			}
		}
	}
	return out
}

func descOf(v any) string {
	m, _ := v.(map[string]any)
	d, _ := m["description"].(string)
	return d
}

func annotationsOf(t json.RawMessage) map[string]bool {
	var x struct {
		Annotations map[string]any `json:"annotations"`
	}
	out := map[string]bool{}
	if json.Unmarshal(t, &x) != nil {
		return out
	}
	for k, v := range x.Annotations {
		if b, ok := v.(bool); ok {
			out[k] = b
		}
	}
	return out
}

var _ = url.Parse
