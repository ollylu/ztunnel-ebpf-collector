# 仅本地 CGO=0 交叉编译产物 + scratch；构建期不需要网络。
FROM scratch
# Required: path of a prebuilt CGO_ENABLED=0 Linux binary in the build context.
ARG BIN
COPY ${BIN} /collector
USER 65532:65532
ENTRYPOINT ["/collector"]
