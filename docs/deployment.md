# 部署入口

仅在已批准的Linux amd64测试节点部署只观察的DaemonSet，复用现有Istio Ambient/ztunnel。

|事项|入口与边界|
|---|---|
|参数|[README](../README.md)：namespace、Pod标签、观察方向及染色头|
|交付|[CI/CD](cicd.md)：静态Go构建、私有仓库、digest与Helm|
|权限|hostPID、root、BPF/PERFMON/SYS_PTRACE、只读BTF/tracefs、seccomp Unconfined；需集群管理员核准|
|Kubernetes元数据|集群pods只读get/list/watch；业务namespace过滤不是RBAC隔离|
|稳定性|预算超限或丢事件会保护停采；不自动放宽宿主权限或重启掩盖保护|
|验证|[公开验证摘要](validation.md)；目标集群仍需独立验收|

Chart不安装Istio、不修改CNI、不重写业务网络或返回值。不要把构建或模板渲染通过当作目标内核加载、协议完整性或性能验收通过。
