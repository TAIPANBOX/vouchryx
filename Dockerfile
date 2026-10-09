# The delegation plane as a published image.
#
# Until now every deployment BUILT this from source on the machine it was
# installing to (components.json's `distribution`: "not distributed: built
# from source, no tag yet"). A lab image built 2026-09-27 with this two-stage
# shape ran correctly in a cluster: static, distroless, non-root, multi-arch.
#
# CGO off is what makes the binary runnable on distroless static AND what
# makes cross-compiling to arm64 free: there is no C toolchain to arrange, so
# the arm64 image costs the same as the amd64 one. Both binaries this
# repository builds, `vouchryx` and `vouchryx-demo`, land in the image; the
# service is the ENTRYPOINT, and the demo client is reached with
# `docker run --entrypoint vouchryx-demo`.
#
# Base images are pinned by digest, not by tag: a tag can move under an
# operator without anyone choosing that, a digest cannot (gate:
# scripts/base-images-pinned-by-digest.sh).
#
# NEEDS BUILDKIT. `$BUILDPLATFORM` is a BuildKit variable, so a legacy-builder
# `docker build` expands it to nothing and fails with "failed to parse
# platform : \"\" is an invalid OS component". BuildKit is the default in
# Docker 23+ and in Docker Desktop; a host without it needs
# `docker buildx build`, or drop the `--platform=` from the line below and
# lose only the cross-compile (arm64 then builds under emulation).
#
# Measured 2026-09-27: `docker buildx build --platform linux/amd64,linux/arm64`
# succeeded, and the native-arch image ran `vouchryx` (healthz 200, a
# public-only JWKS, exit 2 with no config) and `vouchryx-demo` correctly.

FROM --platform=$BUILDPLATFORM golang@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
# Dependencies first, so a code-only change does not re-download the module
# graph on every build.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
# TARGETARCH comes from buildx, one value per platform being built. Building
# FROM the build platform and cross-compiling, rather than emulating the
# target under QEMU, is the difference between a minute and a quarter of an
# hour.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/vouchryx ./cmd/vouchryx
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/vouchryx-demo ./cmd/vouchryx-demo

FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="vouchryx"
LABEL org.opencontainers.image.description="The delegation plane: RFC 8693 token exchange sender-constrained by RFC 9449 DPoP, plus the revocation list every enforcement point polls."
LABEL org.opencontainers.image.source="https://github.com/TAIPANBOX/vouchryx"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/vouchryx /usr/local/bin/vouchryx
COPY --from=build /out/vouchryx-demo /usr/local/bin/vouchryx-demo
# 65532 is distroless's `nonroot` uid. Numeric on purpose: a kubelet with
# runAsNonRoot cannot verify a NAME and refuses the container outright.
USER 65532:65532
# No ENV VOUCHRYX_ADDR here: config.DefaultAddr already resolves to
# 127.0.0.1:4310 unset, and a launcher that wants this reachable from outside
# the pod/container sets VOUCHRYX_ADDR=0.0.0.0:4310 itself. The image does not
# widen the bind on its own (cmd/vouchryx's own bindWarning logs, never
# silently, the moment the configured address is not loopback).
ENTRYPOINT ["/usr/local/bin/vouchryx"]
