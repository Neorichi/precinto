package config

import (
	"reflect"
	"strings"
)

// keyError is a Validate failure of one key of the file: Error() is the
// message as before, and Load also names the line that sets the key
// (UX-09).
type keyError struct {
	key []string // the key's path in the file: {"policy", "min_free"}, {"roots", "md"}
	nth int      // which table of an array of tables ([[roots]]) holds it; -1 outside one
	err error
}

func (e *keyError) Error() string { return e.err.Error() }
func (e *keyError) Unwrap() error { return e.err }

// keyLine returns the 1-based line of the TOML text src that sets key
// (its full dotted path), or the [table] or [[table]] header that opens
// it. With nth >= 0 only the nth table of the array of tables holding the
// key counts. It returns 0 when the key is not found: the text is read
// line by line as precinto writes it (headers, then `key = value` lines,
// dotted and quoted keys included), so a key inside an inline table is
// not located.
func keyLine(src []byte, key []string, nth int) int {
	want := strings.Join(key, ".")
	var table []string
	idx := -1 // index of the current table in its array of tables
	counts := map[string]int{}
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			array := strings.HasPrefix(line, "[[")
			open, closer := "[", "]"
			if array {
				open, closer = "[[", "]]"
			}
			end := strings.Index(line, closer)
			if end < len(open) {
				continue
			}
			table = splitKey(line[len(open):end])
			name := strings.Join(table, ".")
			idx = -1
			if array {
				idx = counts[name]
				counts[name]++
			}
			if name == want && nth < 0 {
				return i + 1
			}
			continue
		}
		eq := assignment(line)
		if eq < 0 {
			continue
		}
		full := append(append([]string(nil), table...), splitKey(line[:eq])...)
		if strings.Join(full, ".") == want && (nth < 0 || idx == nth) {
			return i + 1
		}
	}
	return 0
}

// assignment returns the index of the '=' of a `key = value` line (outside
// a quoted key), or -1.
func assignment(line string) int {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '=':
			return i
		}
	}
	return -1
}

// splitKey splits a dotted TOML key into its parts, unquoted and trimmed.
func splitKey(s string) []string {
	var parts []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
		case c == '.':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(parts, strings.TrimSpace(cur.String()))
}

// suggestKey returns the key config.toml accepts next to an unknown one
// that is nearest to its last part (at most two edits away, a swap of two
// neighbours counting as one, and at most half its length), or "".
func suggestKey(key []string) string {
	if len(key) == 0 {
		return ""
	}
	name := key[len(key)-1]
	best, bestD := "", -1
	for _, k := range knownKeys(key[:len(key)-1]) {
		if d := editDistance(name, k); bestD < 0 || d < bestD {
			best, bestD = k, d
		}
	}
	if bestD < 1 || bestD > 2 || 2*bestD > len(name) {
		return ""
	}
	return best
}

// knownKeys lists the keys config.toml accepts in the table at parent
// (map keys such as a harness id are free, arrays of tables are walked
// through), from the toml tags of Config.
func knownKeys(parent []string) []string {
	t := reflect.TypeOf(Config{})
	for _, p := range parent {
		t = elem(t)
		switch t.Kind() {
		case reflect.Map:
			t = t.Elem() // p names an entry: [harness.<id>]
		case reflect.Struct:
			f, ok := fieldByKey(t, p)
			if !ok {
				return nil
			}
			t = f.Type
		default:
			return nil
		}
	}
	t = elem(t)
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for i := 0; i < t.NumField(); i++ {
		if k := tomlKeyOf(t.Field(i)); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func elem(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func fieldByKey(t reflect.Type, key string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		if tomlKeyOf(t.Field(i)) == key {
			return t.Field(i), true
		}
	}
	return reflect.StructField{}, false
}

// tomlKeyOf is the TOML key of a struct field ("" when it has none).
func tomlKeyOf(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
	switch name {
	case "-":
		return ""
	case "":
		return f.Name
	}
	return name
}

// editDistance is the optimal string alignment distance of a and b:
// insertions, deletions, substitutions and swaps of two neighbours.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
