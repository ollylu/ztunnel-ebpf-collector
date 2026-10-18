# GitHub发布前必须脱敏

本项目任何GitHub提交/推送、PR、Release或附件上传前，必须先脱敏并审查将公开的内容和历史；不能把“没发现密钥”当作“没有敏感信息”。

|门禁|必须执行|
|---|---|
|发布来源|使用独立的脱敏公开工作目录；禁止直接推送私有研发历史或私有交接包|
|凭据|检查访问密钥、token、私钥、Kubeconfig、Cookie/Authorization、连接串及其编码形式；发现真实凭据先停止发布并处理泄露风险|
|环境隐私|删除/替换真实内网地址、内部域名、云资源ID、节点/Pod清单、账号/个人路径、业务数据与协作记录|
|历史|审查将推送的全部提交、分支/标签及提交元数据；仅删除当前文件不能清除历史|
|非文本/附件|单独检查截图、PDF、压缩包、镜像层、二进制字符串与忽略的缓存；不直接压缩整个开发目录|
|测试占位|仅保留可证明为合成的地址/UID/凭据占位；误报记录依据，不用宽泛白名单隐藏风险|
|自动扫描|Gitleaks完整历史扫描无真实凭据命中；工具缺失、异常或扫描不完整时阻止推送|
|审阅确认|按固定HEAD记录脱敏复核及扫描结果；每次新提交须重新审阅，不沿用旧SHA|
|禁止绕过|不使用--no-verify、临时禁用hooks或all/mirror/force推送绕过审核|

自动密钥扫描不能识别所有业务隐私，因此仍需逐项审查文档、测试样本及新增文件。扫描结论只覆盖已检查的固定内容，不能保证未来修改永远安全。

## 本地推送门禁

`.githooks/pre-push`在实际Git push前执行：

1. 只允许本地显式标记的公开工作目录；私有目录默认拒绝。
2. 要求工作区干净，待推送对象等于已经审阅的当前HEAD。
3. 执行Gitleaks完整历史扫描，缺工具或失败即停止，不打印未脱敏凭据。

先安装固定版本Gitleaks并启用项目级hooks（不改变全局配置）：

```sh
go install github.com/zricethezav/gitleaks/v8@v8.30.1
export GITLEAKS_BIN="$HOME/go/bin/gitleaks"
make hooks-enable
```

`make hooks-enable`也会启用已有post-commit构建hook；它执行本项目本地CI，不自动推送或部署。新机器克隆不会自动继承本地Git配置，需再次启用。

仅在确认当前目录是脱敏公开副本、完成本次人工/代理内容审查及实际扫描后，才能在**本地**记录：

```sh
git config --local security.publicRelease true
# 完成审阅后才执行；不能将此命令当作自动审核或跳过扫描的手段。
git config --local security.reviewedPublicSHA "$(git rev-parse HEAD)"
git push origin main
```

私有研发目录应保持`security.publicRelease=false`。门禁暂仅支持推送当前已审阅HEAD，不允许旧分支对象、删除或带独立对象的annotated tag；其他发布形式须先扩展审查与门禁覆盖，不临时绕过。

本地hooks可被具有本机控制权的人绕过，并非GitHub服务端保护；本规则要求不得绕过。启用GitHub服务端secret push protection可再提供一层保护，但不替代环境隐私审查，本项目不把未配置的服务端保护宣称为已生效。
