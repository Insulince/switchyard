package main

import _ "embed"

// indexHTML is the whole status view: one file, no build step, no CDN.
//
// It is embedded rather than read from disk so the container image needs
// nothing mounted but the config, and so the page can never be out of step
// with the JSON shape the binary serves it.
//
//go:embed index.html
var indexHTML []byte
