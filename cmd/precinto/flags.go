package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// errHelp is returned by parse when -h/--help was given (exit 0 after the
// usage text).
var errHelp = flag.ErrHelp

// flags is a flag.FlagSet for one subcommand that accepts flags before,
// between and after positional arguments (`protect DIR --md all`), with
// `--` ending flag parsing. Errors are reported by the caller, never by the
// flag package.
type flags struct {
	*flag.FlagSet
	cmd     string
	usage   string
	summary string
}

// newFlags returns the flag set of the command name (its usage line comes
// from the dispatch table).
func newFlags(name string) *flags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := &flags{FlagSet: fs, cmd: name}
	if c, ok := lookup(name); ok {
		f.usage, f.summary = c.usage, c.summary
	}
	return f
}

// parse parses args with flags interspersed among positional arguments and
// returns the positional ones. Everything after a `--` is positional.
func (f *flags) parse(args []string) ([]string, error) {
	var pos []string
	rest := args
	for {
		before := rest
		if err := f.FlagSet.Parse(rest); err != nil {
			return nil, err
		}
		rest = f.FlagSet.Args()
		consumed := len(before) - len(rest)
		if consumed > 0 && before[consumed-1] == "--" && !f.isFlagValue(before, consumed-1) {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		rest = rest[1:]
	}
}

// parseHead parses flags up to the first positional argument or `--` and
// returns everything after it verbatim (`run [flags] -- CMD ARGS…`, where the
// command's own flags must not be parsed).
func (f *flags) parseHead(args []string) ([]string, error) {
	if err := f.FlagSet.Parse(args); err != nil {
		return nil, err
	}
	return f.FlagSet.Args(), nil
}

// isFlagValue reports whether args[i] is the value of the flag before it
// (`--root --` names a folder called "--", not the terminator).
func (f *flags) isFlagValue(args []string, i int) bool {
	if i == 0 {
		return false
	}
	prev := args[i-1]
	if !strings.HasPrefix(prev, "-") || prev == "-" || prev == "--" || strings.Contains(prev, "=") {
		return false
	}
	fl := f.FlagSet.Lookup(strings.TrimLeft(prev, "-"))
	if fl == nil {
		return false
	}
	if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
		return false
	}
	return true
}

// printUsage writes the usage line, the summary and the flag defaults.
func (f *flags) printUsage(w io.Writer) {
	fmt.Fprintf(w, "usage: precinto %s\n", f.usage)
	if f.summary != "" {
		fmt.Fprintf(w, "\n%s\n", f.summary)
	}
	first := true
	f.FlagSet.VisitAll(func(fl *flag.Flag) {
		if first {
			fmt.Fprintln(w, "\nFlags:")
			first = false
		}
		name, help := flag.UnquoteUsage(fl)
		head := "  --" + fl.Name
		if name != "" {
			head += " " + name
		}
		if def := fl.DefValue; def != "" && def != "false" && def != "0" && def != "0s" && def != "[]" {
			help += " (default " + def + ")"
		}
		fmt.Fprintf(w, "%s\n      %s\n", head, help)
	})
}

// handleParse turns a parse error into an exit code: help prints the usage
// on stdout (exit 0), anything else is a usage error on stderr (exit 2).
// ok is false when the command must return code.
func (a *app) handleParse(f *flags, err error) (code int, ok bool) {
	if err == nil {
		return 0, true
	}
	if errors.Is(err, errHelp) {
		f.printUsage(a.out)
		return exitOK, false
	}
	return a.usageFail(f, err.Error()), false
}

// usageFail prints a usage error for f and returns exit 2.
func (a *app) usageFail(f *flags, msg string) int {
	fmt.Fprintf(a.err, "precinto %s: %s\n", f.cmd, oneLineText(msg))
	fmt.Fprintf(a.err, "usage: precinto %s\n", f.usage)
	return exitUsage
}

// stringList is a repeatable string flag (--factor se --factor passphrase).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	if v == "" {
		return errors.New("empty value")
	}
	*s = append(*s, v)
	return nil
}

// optInt is an int flag that records whether it was set.
type optInt struct {
	v   int
	set bool
}

func (o *optInt) String() string { return strconv.Itoa(o.v) }

func (o *optInt) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return fmt.Errorf("want a non-negative number, got %q", s)
	}
	o.v, o.set = n, true
	return nil
}

// oneOfFlag validates an enum flag value ("" = not given).
func oneOfFlag(name, v string, allowed ...string) error {
	if v == "" {
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return usageErrorf("--%s must be one of %s", name, strings.Join(allowed, ", "))
}

// exclusive returns a usage error when more than one of the named flags is
// set.
func exclusive(set map[string]bool) error {
	var on []string
	for name, v := range set {
		if v {
			on = append(on, "--"+name)
		}
	}
	if len(on) > 1 {
		return usageErrorf("use only one of %s", strings.Join(sortedStrings(on), ", "))
	}
	return nil
}
