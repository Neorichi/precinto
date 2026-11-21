// Command buildprobe is a helper program for the testkit self-tests: it
// prints the build tags it was compiled with, so a test can check what
// testkit's builder passed to go build.
package main

import "fmt"

func main() { fmt.Println(tags) }
