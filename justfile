# switchyard development recipes.
#
#   just            list all recipes
#
# Recipes are deliberately plain commands with no shell syntax, so they behave
# the same under cmd.exe, Git Bash and a Linux sh.

# List available recipes.
default:
    @just --list

# Build the binary into ./switchyard.
build:
    go build -o switchyard .

# Build, then run against a config file.
run config="config.json": build
    ./switchyard -config {{config}}

# Print the version this working tree builds to.
version:
    go run . -version

# Run the tests.
test:
    go test ./...

# Run the tests with the race detector, as CI does.
race:
    go test -race ./...

# Format every Go file in place.
fmt:
    gofmt -w .

# List files that are not gofmt'd. Silence is the pass.
fmt-check:
    gofmt -l .

# Everything CI checks. CI fails the build on gofmt output; here it prints.
check: fmt-check check-js
    go vet ./...
    go test -race ./...

# Syntax-check the dashboard script embedded in index.html.
check-js:
    node tools/checkjs.js

# Print the dashboard URL with the performance HUD enabled.
perf host="127.0.0.1:7160":
    @echo http://{{host}}/?perf=1

# Remove build artefacts.
clean:
    rm -f switchyard switchyard.exe

# Build the container image locally (version defaults to dev).
image version="dev":
    docker build --build-arg VERSION={{version}} -t switchyard:{{version}} .

# Run the locally built image against ./config.
image-run version="dev":
    docker run --rm -p 7160:7160 -p 23401-23402:23401-23402 -v "{{justfile_directory()}}/config:/config" switchyard:{{version}}

# Show the commit a release would tag. Changes nothing.
release-dry version:
    @echo would tag v{{version}} at:
    git rev-parse --short HEAD
    @echo publish with: git push origin v{{version}}

# Create the release tag locally. Does not push -- pushing is what publishes.
tag version:
    git tag -a v{{version}} -m "switchyard v{{version}}"
    @echo tagged v{{version}} locally. publish with: git push origin v{{version}}
