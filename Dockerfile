# switchyard has no third-party dependencies, so there is no go.sum to copy
# and no module download step -- the build is just the toolchain and these
# source files.
# BUILDPLATFORM, not the target: the builder runs natively and Go cross-
# compiles. Without this the arm64 image is produced by running the entire
# compile inside an emulated arm64 container under QEMU -- many times slower,
# for a build that has CGO disabled and therefore needs nothing from the
# target platform at all.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY *.go ./
# The status page is go:embed'ed, so it is a build input, not a runtime asset.
COPY index.html ./

# THE VERSION HAS TO BE HANDED IN.
#
# version.go treats the git tag as the only source of truth, and falls back to
# the VCS revision that Go stamps into the build info. Neither is available
# here: the build context is source files only, with no .git directory, so an
# unadorned build inside this image reports "dev" forever -- including for a
# tagged release. Anyone running the container then has no way to say which
# version they are on, which is the whole point of the scheme.
#
# The release workflow passes both. A plain `docker build` still works and
# still honestly says "dev".
ARG VERSION=dev
ARG COMMIT=

# Supplied by buildx for each requested platform.
ARG TARGETOS
ARG TARGETARCH

# CGO off so the binary runs on a bare alpine (or scratch) runtime without
# needing the toolchain's libc.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath       -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}"       -o /switchyard .

FROM alpine:3.20

# wget comes from busybox and is only here for the healthcheck.
RUN adduser -D -H -s /sbin/nologin switchyard

COPY --from=build /switchyard /usr/local/bin/switchyard

USER switchyard

# The config is mounted, not baked, so pool and rig changes do not require a
# rebuild -- same idiom the datum-gateway containers use.
ENTRYPOINT ["switchyard"]
CMD ["-config", "/config/config.json"]
