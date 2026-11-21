package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestPolicyRulesCoverEveryKey: a Policy field without a rule would be
// ignored by Diff and Strictest (silently weakening the merge).
func TestPolicyRulesCoverEveryKey(t *testing.T) {
	var tags []string
	pt := reflect.TypeOf(Policy{})
	for i := 0; i < pt.NumField(); i++ {
		tags = append(tags, strings.Split(pt.Field(i).Tag.Get("toml"), ",")[0])
	}
	var keys []string
	for _, r := range policyRules {
		keys = append(keys, r.name())
	}
	if !slices.Equal(tags, keys) {
		t.Fatalf("policy rules %q\ndo not match Policy fields %q (same order)", keys, tags)
	}
	// Rule i reads exactly field i, and merges into exactly field i.
	for i := 0; i < pt.NumField(); i++ {
		var p Policy
		f := reflect.ValueOf(&p).Elem().Field(i)
		switch f.Kind() {
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int64:
			f.SetInt(1)
		case reflect.String:
			f.SetString("x")
		default:
			t.Fatalf("field %s: unhandled kind %s", pt.Field(i).Name, f.Kind())
		}
		for j, r := range policyRules {
			if _, changed := r.diff(&Policy{}, &p); changed != (i == j) {
				t.Errorf("rule %s sees field %s: %v", r.name(), pt.Field(i).Name, changed)
			}
			var dst Policy
			r.merge(&dst, &p, &p)
			if moved := dst != (Policy{}); moved != (i == j) {
				t.Errorf("rule %s merges field %s: %v", r.name(), pt.Field(i).Name, moved)
			}
		}
	}
}

func TestCmpVersion(t *testing.T) {
	ordered := []string{"", "0.1", "0.154.0", "1.0.0-beta", "1.0.0", "v1.0.1", "2.1.295", "2.1.329+build.7", "10.0", "garbage"}
	for i := range ordered {
		for j := range ordered {
			got := cmpVersion(ordered[i], ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Errorf("cmpVersion(%q, %q) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	for _, eq := range [][2]string{{"1.0", "1.0.0"}, {"v2.1", "2.1"}, {"garbage", "x.y"}, {"1.0+a", "1.0+b"}} {
		if c := cmpVersion(eq[0], eq[1]); c != 0 {
			t.Errorf("cmpVersion(%q, %q) = %d, want 0", eq[0], eq[1], c)
		}
	}
	for _, bad := range []string{"1..2", "1.-2", "1.x", ".1", "1.99999999999999999999", "-1"} {
		if r, _, _ := parseVersion(bad); r != 2 {
			t.Errorf("parseVersion(%q) rank %d, want unparseable", bad, r)
		}
	}
}
