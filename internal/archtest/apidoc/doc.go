// Command apidoc renders the exported Go API of every package listed in
// archtest.Packages as Markdown, grouped by owner: the generated part of
// docs/API.md, between the BEGIN/END GENERATED markers. From the
// repository root:
//
//	go run ./internal/archtest/apidoc                  # print to stdout
//	go run ./internal/archtest/apidoc -splice docs/API.md  # rewrite between markers
//	go run ./internal/archtest/apidoc -check docs/API.md   # exit 1 if out of date
//
// Owner: G7 (CLI). Imports: stdlib, internal/archtest.
package main
