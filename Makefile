SHELL := /bin/sh
REVISION := $(strip $(shell git rev-parse --verify HEAD 2>/dev/null || echo unknown))
VERSION ?= 0.1.0
IMAGE_REPOSITORY ?= ztunnel-ebpf-collector
IMAGE_ARCH ?= amd64
DIRTY := $(shell git status --porcelain 2>/dev/null | head -1)
ifeq ($(DIRTY),)
DIST := dist/$(REVISION)
CLEAN := 1
IMAGE_TAG := $(IMAGE_REPOSITORY):$(REVISION)-$(IMAGE_ARCH)
else
DIST := dist/.dirty/$(REVISION)
CLEAN := 0
IMAGE_TAG :=
endif
RUNNER_BIN := dist/.tools/runner
CI_RUNNER ?= $(RUNNER_BIN)
CI_CHECK_CMD ?= $(MAKE) check
CI_TIMEOUT_CHECK ?= 600s
CI_TIMEOUT_IMAGE ?= 900s
CI_TIMEOUT_CHART ?= 300s
LDFLAGS := -X main.revision=$(REVISION) -X main.version=$(VERSION) -X main.sourceMode=worktree
export CGO_ENABLED := 0

.PHONY: check itest build image push chart ci hooks-enable clean runner

check: ## 快速门禁：格式、vet、unit test、无 C（不含集成入口，防递归）
	@set -e; \
	if [ -n "$$(gofmt -l cmd internal tests build)" ]; then echo "gofmt: files need formatting" >&2; gofmt -l cmd internal tests build; exit 1; fi; \
	CGO_ENABLED=0 go vet ./cmd/... ./internal/... ./build/... ./tests/...; \
	ZTUNNEL_CHECK_ACTIVE=1 CGO_ENABLED=0 go test ./cmd/... ./internal/... ./build/... ./tests/... -count=1; \
	if grep -rq 'import "C"' --include='*.go' --exclude='*_test.go' cmd internal build; then echo "cgo: import \"C\" found" >&2; exit 1; fi; \
	if find cmd internal tests build -name '*.c' -o -name '*.cc' | grep -q .; then echo "cgo: C sources found" >&2; exit 1; fi; \
	cgo_one="CGO_ENABLED"'=1'; \
	if grep -rq "$$cgo_one" Makefile .githooks 2>/dev/null; then echo "cgo: build entry enables cgo" >&2; exit 1; fi; \
	echo "make check: OK (go test, go vet, no-C)"

runner: ## 编译本机 runner 二进制（保留真实退出码；go run 会把 125 映射为 1）
	@set -e; mkdir -p dist/.tools; CGO_ENABLED=0 go build -o $(RUNNER_BIN) ./build/runner; echo "runner: $(RUNNER_BIN)"

itest: ## 显式集成入口（会调用 make；带超时与防重入）
	@set -e; CGO_ENABLED=0 go test -tags=integration ./tests/ -count=1 -timeout 300s

build: ## 构建制品（锁 fail-closed；已有成功目录不覆盖；整组一次发布）
	@set -e; mkdir -p dist; \
	if ! mkdir dist/.build.lock 2>/dev/null; then \
	  echo "build lock present: refusing to run (fail-closed; no automatic stale reclaim)." >&2; \
	  echo "Verify no build is running, then remove dist/.build.lock manually." >&2; exit 3; \
	fi; \
	echo $$$$ > dist/.build.lock/owner.pid; \
	trap 'rm -rf dist/.build.lock' EXIT INT TERM HUP; \
	tmp=$$(mktemp -d dist/.staging.XXXXXX); \
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $$tmp/collector-linux-arm64 ./cmd/collector; \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $$tmp/collector-linux-amd64 ./cmd/collector; \
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $$tmp/collector-darwin-arm64 ./cmd/collector; \
	go run ./build/receipt -dist $$tmp -out $$tmp/build-receipt.json -revision $(REVISION) -dirty=$$( [ "$(CLEAN)" = "1" ] && echo false || echo true ); \
	if [ -d "$(DIST)" ]; then \
	  echo "publish: existing successful $(DIST) kept (no overwrite); staging discarded" >&2; rm -rf $$tmp; \
	else \
	  mkdir -p "$$(dirname "$(DIST)")"; mv $$tmp "$(DIST)"; \
	fi; \
	echo "make build: $(DIST) (candidate; sourceMode=worktree, unpublished)"

image: build ## 仅清洁固定源可出镜像（无网络 build；本地标签 + imageID）
	@set -e; \
	if [ "$(CLEAN)" != "1" ]; then echo "image: dirty tree must not produce/overwrite a fixed-SHA image (commit first)" >&2; exit 1; fi; \
	case "$(IMAGE_ARCH)" in amd64|arm64) ;; *) echo "unsupported image architecture" >&2; exit 1;; esac; \
	ctx=$$(mktemp -d dist/.image.XXXXXX); \
	trap 'rm -rf "$$ctx"' EXIT INT TERM HUP; \
	cp $(DIST)/collector-linux-$(IMAGE_ARCH) "$$ctx/collector"; \
	docker build --platform linux/$(IMAGE_ARCH) --network none -f Dockerfile --build-arg BIN=collector -t $(IMAGE_TAG) "$$ctx" >/dev/null; \
	id=$$(docker image inspect --format '{{.Id}}' $(IMAGE_TAG)); \
	printf '%s\n' "$$id" > $(DIST)/image-id.txt; \
	go run ./build/receipt -dist $(DIST) -out $(DIST)/build-receipt.json -revision $(REVISION) -dirty=false -image=$(IMAGE_TAG) -image-id=$$id; \
	echo "image=$(IMAGE_TAG) id=$$id"

push: image ## 显式推送；仓库登录由CI Secret提供，本地ci不会推送
	@set -e; \
	if [ "$(IMAGE_REPOSITORY)" = "ztunnel-ebpf-collector" ]; then echo "push: set IMAGE_REPOSITORY to your registry/repository" >&2; exit 1; fi; \
	docker push $(IMAGE_TAG); \
	docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' $(IMAGE_TAG) > $(DIST)/registry-digests.txt; \
	echo "registry manifest references: $(DIST)/registry-digests.txt"

chart: ## 打包 Chart 并把 tgz 纳入 hash 回执（保留既有 image 绑定）
	@set -e; mkdir -p $(DIST); helm lint charts/ztunnel-ebpf-collector >/dev/null; helm package charts/ztunnel-ebpf-collector -d $(DIST) >/dev/null; \
	img=""; imgid=""; \
	if [ -n "$(IMAGE_TAG)" ] && [ -f $(DIST)/image-id.txt ]; then img="$(IMAGE_TAG)"; imgid=$$(cat $(DIST)/image-id.txt); fi; \
	go run ./build/receipt -dist $(DIST) -out $(DIST)/build-receipt.json -revision $(REVISION) -dirty=$$( [ "$(CLEAN)" = "1" ] && echo false || echo true ) $${img:+-image=$$img} $${imgid:+-image-id=$$imgid}; \
	echo "make chart: $(DIST)"

ci: runner ## 串行 check → image(含 build) → chart（单壳持锁；子进程有界；失败写回执）
	@set -e; mkdir -p dist; \
	if ! mkdir dist/.ci.lock 2>/dev/null; then echo "ci already running; skipping" >&2; exit 3; fi; \
	echo $$$$ > dist/.ci.lock/owner.pid; \
	cleanup_unconfirmed=0; \
	run_bounded() { lim=$$1; shift; rc=0; $(CI_RUNNER) -timeout "$$lim" -- "$$@" || rc=$$?; if [ "$$rc" -eq 125 ]; then cleanup_unconfirmed=1; echo "cleanup unconfirmed (125): dist/.ci.lock will be kept for manual verification" >&2; fi; return $$rc; }; \
	trap 'rc=$$?; if [ "$$cleanup_unconfirmed" = "1" ]; then echo "keeping dist/.ci.lock (cleanup unconfirmed; SIGKILL does not promise automatic recovery — verify manually)" >&2; else rm -rf dist/.ci.lock; fi; if [ $$rc -ne 0 ]; then mkdir -p dist/.failures; f=dist/.failures/$$(date -u +%Y%m%dT%H%M%SZ)-$(REVISION).txt; printf "stage=ci\nrevision=%s\nclean=%s\nexit=%s\ntime_utc=%s\n" "$(REVISION)" "$(CLEAN)" "$$rc" "$$(date -u +%FT%TZ)" > $$f; echo "ci failed (exit $$rc); failure receipt: $$f" >&2; fi' EXIT INT TERM HUP; \
	run_bounded $(CI_TIMEOUT_CHECK) $(CI_CHECK_CMD); \
	run_bounded $(CI_TIMEOUT_IMAGE) $(MAKE) image; \
	run_bounded $(CI_TIMEOUT_CHART) $(MAKE) chart; \
	echo "make ci: OK"

hooks-enable: ## 显式启用本项目本地 hook（仅仓库级，不写全局）
	@set -e; git config core.hooksPath .githooks; chmod +x .githooks/post-commit; echo "hooks enabled: core.hooksPath=.githooks (repo-local)"

clean:
	@rm -rf dist
