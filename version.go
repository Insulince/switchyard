package main

import "runtime/debug"

// version is the release this binary was built from.
//
// Same contract as blockwatch's, deliberately: THE GIT TAG IS THE ONLY SOURCE
// OF TRUTH. No VERSION file, no constant to bump, no version string committed
// anywhere in the tree -- each of those is a second place the version lives,
// and once two places exist they disagree. The failure is quiet: a v1.4.0 tag
// shipping a binary that reports 1.3.0 because the bump commit was forgotten.
//
//	git tag v1.4.0 && git push --tags
//
// CI reads the tag and passes it here via -ldflags "-X main.version=...".
//
// Left as "dev" for ordinary `go build`, which is honest: a working-tree build
// is not any released version.
var version = "dev"

// commit is the short revision, filled the same way. Answers "which dev build
// is this?" when version is still "dev".
var commit = ""

// versionString is what gets shown to a person. With no ldflags at all, Go's
// own build info still carries the VCS revision, so a dev build can identify
// itself without any build tooling.
func versionString() string {
	if version != "dev" {
		return version
	}
	if commit != "" {
		return "dev+" + commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return "dev+" + s.Value[:7]
			}
		}
	}
	return "dev"
}
