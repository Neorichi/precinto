// Command precinto is the single binary: CLI, hook handler, wrapper, sweeper
// and daemon (SPEC §16).
//
// Owner: G7 (CLI). It wires every internal package; nothing imports it.
// Exit codes: 0 ok, 1 error, 2 usage, 3 locked/unauthorized, 4 live
// (refused to touch live data), 5 verification failed.
package main
