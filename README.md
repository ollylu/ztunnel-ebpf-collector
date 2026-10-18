# ztunnel 染色请求采集器

面向 **Linux / Ubuntu 24 / amd64** 的 Kubernetes 节点采集器，以 Go + cilium/ebpf/asm 实现。每个选中节点部署一个 DaemonSet Pod，观察 ztunnel，自动识别已支持的 HTTP/1、HTTP/2、gRPC，只向 stdout 输出染色请求及响应。处理后释放，不增加应用结果存储。

**本项目内部测试部署使用 amd64。** `make ci` 默认构建 `linux/amd64` 镜像，Chart 将常驻采集器限制在 Linux amd64 节点。Mac只是开发机，其架构不决定部署镜像架构。

## GitHub发布规则

**提交/推送GitHub前必须先脱敏，并检查文件、历史及发布附件。** 仅从独立的脱敏公开工作目录发布，不能上传私有研发包或原历史；每次新提交需重新审查和扫描。本地pre-push门禁及安装方式见[发布脱敏规则](PUBLICATION_POLICY.md)。

## 配置方式与优先关系

|配置方式|当前支持|使用方法|
|---|---|---|
|程序启动参数|直接支持|`/collector node --namespace orders --namespace payments ...`|
|Helm values|直接支持，推荐DaemonSet部署使用|Chart将values转为容器启动参数|
|CI/CD环境变量|通过Helm注入|流水线环境变量经`--set-json`/`--set-string`转为values，见后文|
|Kubernetes容器环境变量|通过args注入|Pod `env`定义变量，`args`使用`$(变量名)`；程序本身不直接读取这些业务配置环境变量|

**不要只给容器设置`COLLECTOR_NAMESPACES`或`MARKER_HEADER`就认为会生效**：目前没有这类原生环境变量入口。使用已有启动参数或明确的变量转参数方式。Helm优先级为Chart默认值 → `-f`环境文件 → `--set*`覆盖；命令行覆盖文件配置。一个实例使用一组染色头名称/值和一个业务标签选择器。

## 可调整参数

|用途|启动参数|Helm values|要求与默认值|
|---|---|---|---|
|本节点名称|`--node NODE`|自动注入`spec.nodeName`|必需；无需给每台节点单独配置|
|多个业务namespace|重复`--namespace NS`|`daemon.namespaces: [orders, payments]`|必需，1–32个精确名称；不是正则/通配；不接受逗号拼在一个CLI参数中|
|业务Pod过滤|`--selector observe=yes`|`daemon.selector`|必需，当前支持单个精确`key=value`，namespace与标签同时命中才采集|
|观察方向|`--direction both`|`daemon.direction`|`inbound`/`outbound`/`both`；程序默认`inbound`，内部示例使用`both`|
|染色头名称|`--marker-header X-Company-Debug`|`captureConfig.markerHeader`|必需、可自定义；不是写死X-trace或Debug-Token|
|染色头值|`--marker-value enabled`|`captureConfig.markerValue`|必需、按值匹配，不支持正则；YAML中建议始终加引号|
|选部署节点|不属于业务CLI|`daemon.nodeSelector`|节点标签；自动附加linux/amd64限制|
|镜像与凭据|不属于业务CLI|`image.repository/tag/digest`、`imagePullSecrets`|支持私有仓库及固定manifest digest|
|资源与调度|不属于业务CLI|`daemon.resources/tolerations/priorityClassName`|保持既有保护预算，详见[CI/CD说明](docs/cicd.md)|

旧的`daemon.namespace`单namespace配置仍兼容，但不能与`daemon.namespaces`同时设置。修改namespace、标签、方向或染色规则需要重新启动进程；使用Helm upgrade会滚动更新DaemonSet，**不是热更新**。新增/删除业务Pod则由现有list/watch自动发现，无需重启采集器。

`inbound`表示观察选中Pod接收的调用，`outbound`表示观察选中Pod发起的调用；每侧均可输出请求和回复，通过`direction: request/response`区分。`both`可能在调用两端各输出一对，不是全局去重。

## 推荐：通过Helm部署

将[内部环境values示例](charts/ztunnel-ebpf-collector/values-internal-test.yaml)复制到环境配置仓库，按需修改。例如：

```yaml
syntheticReplay: false
capture: false
image:
  repository: registry.example.com/observability/ztunnel-ebpf-collector
  tag: "<完整GitSHA>-amd64"
  digest: "" # CD可覆盖为仓库manifest sha256 digest，非本机image ID
  pullPolicy: IfNotPresent
imagePullSecrets:
  - name: registry-auth # 已存在于采集器namespace

daemon:
  enabled: true
  namespaces: [orders, payments, shared-api]
  selector: "observe=yes"
  direction: both
  nodeSelector: {} # 首轮可限制到批准的测试节点标签

captureConfig:
  markerHeader: X-Company-Debug
  markerValue: "enabled"
```

目标业务Pod需同时在上述namespace内且包含`observe: "yes"`标签；标签放在Deployment的`spec.template.metadata.labels`。namespace白名单是**业务范围**，`-n ztunnel-sensor`是**采集器自己的部署namespace**，二者不用相同。没有匹配目标时不会自动扩大到全部Pod。

```sh
helm upgrade --install collector ./charts/ztunnel-ebpf-collector \
  --kubeconfig /path/to/internal-test-kubeconfig \
  -n ztunnel-sensor --create-namespace \
  -f values-internal.yaml --atomic --wait --timeout 5m
```

默认Chart是回放模式，真实常驻采集必须设置`daemon.enabled=true`、`syntheticReplay=false`、`capture=false`。当前常驻模式仅观察ztunnel，不需要按HTTP或gRPC分别部署采集器，也不需要为各业务Pod指定协议类型。

## CI/CD：用环境变量覆盖部署参数

以下变量只是流水线约定名称，由Shell展开并传给Helm；**不是采集器原生环境变量**。多个namespace用JSON数组，避免逗号和Helm列表转义问题：

```sh
set -eu
export COLLECTOR_NAMESPACES_JSON='["orders","payments","shared-api"]'
export COLLECTOR_SELECTOR='observe=yes'
export COLLECTOR_DIRECTION='both'
export COLLECTOR_MARKER_HEADER='X-Company-Debug'
export COLLECTOR_MARKER_VALUE='enabled'

helm upgrade --install collector ./charts/ztunnel-ebpf-collector \
  --kubeconfig /path/to/internal-test-kubeconfig \
  -n ztunnel-sensor --create-namespace -f values-internal.yaml \
  --set-json daemon.namespaces="$COLLECTOR_NAMESPACES_JSON" \
  --set-string daemon.selector="$COLLECTOR_SELECTOR" \
  --set-string daemon.direction="$COLLECTOR_DIRECTION" \
  --set-string captureConfig.markerHeader="$COLLECTOR_MARKER_HEADER" \
  --set-string captureConfig.markerValue="$COLLECTOR_MARKER_VALUE" \
  --atomic --wait --timeout 5m
```

用实际请求中的header名称和值替换示例。对于包含逗号等Helm特殊字符的值，建议写到受控values文件中，避免`--set-string`的分隔符解析。构建、仓库推送、digest部署、权限与回退完整流程见[CI/CD说明](docs/cicd.md)。

## 不使用Helm时：直接启动参数

在已具备Chart所需hostPID、BPF权限、只读BTF/tracefs挂载、服务账号CA/token及状态目录的Linux amd64采集容器中：

```sh
/collector node \
  --node cn-internal-worker-01 \
  --namespace orders \
  --namespace payments \
  --namespace shared-api \
  --selector observe=yes \
  --direction both \
  --marker-header X-Company-Debug \
  --marker-value enabled
```

namespace通过重复参数传入，**不是**`--namespace orders,payments`。当前常驻入口依赖集群内API和ServiceAccount凭据，不能把这条命令当作普通Mac或无权限Docker容器的完整启动方案。

如果内部平台只能通过环境变量传配置，可在自己的Pod模板中显式映射到args。下面是`containers[]`中的env/args片段，替换相应字段；不是完整Pod，也不是直接放到现有Chart values中的字段：

```yaml
env:
  - name: NODE_NAME
    valueFrom:
      fieldRef: {fieldPath: spec.nodeName}
  - {name: BUSINESS_NS_1, value: orders}
  - {name: BUSINESS_NS_2, value: payments}
  - {name: BUSINESS_SELECTOR, value: "observe=yes"}
  - {name: BUSINESS_MARKER_HEADER, value: X-Company-Debug}
  - {name: BUSINESS_MARKER_VALUE, value: "enabled"}
args:
  - node
  - --node
  - $(NODE_NAME)
  - --namespace
  - $(BUSINESS_NS_1)
  - --namespace
  - $(BUSINESS_NS_2)
  - --selector
  - $(BUSINESS_SELECTOR)
  - --direction
  - both
  - --marker-header
  - $(BUSINESS_MARKER_HEADER)
  - --marker-value
  - $(BUSINESS_MARKER_VALUE)
```

这是Kubernetes对args的变量替换，镜像不需要shell。namespace数量改变时要相应增减参数对；数量不固定的流水线推荐用前面的Helm JSON数组方式。

## 染色匹配与验证

- 示例`X-Company-Debug: enabled`可替换为公司自己的标识。头名称大小写不敏感；值区分大小写，匹配时去除头值两端空格/Tab。
- 只看当前请求完整初始headers/metadata；重复染色头或歧义不放行，不能用响应头或前一请求的标记给整条连接染色。
- 头名最多128字节、配置值最多256字节；配置值为可打印ASCII且无首尾空格/Tab，不允许Host/Content-Length等协议控制头作为标记。
- 服务间标记由应用/网关透传；采集器不改写请求或自动注入头。gRPC同样需在初始metadata携带标记。

```sh
kubectl --kubeconfig /path/to/internal-test-kubeconfig -n ztunnel-sensor get ds,pods
kubectl --kubeconfig /path/to/internal-test-kubeconfig -n ztunnel-sensor \
  logs -l app.kubernetes.io/instance=collector-node --prefix --since=5m --tail=100
# 向实际业务入口发送；URL替换为你们已有的测试业务地址
curl -H 'X-Company-Debug: enabled' http://your-test-service.example/api
```

再发送一条不带染色头的请求，确认不输出其请求/响应正文。Ready只证明加载及元数据状态，不能代替真实新请求验证。Chart及多namespace参数已测试，内部仓库推拉、节点权限和真实业务需在内部测试环境验收。

## 输出字段说明

以下对应当前常驻`node`入口的JSON记录，字段依据[Record定义](internal/replay/replay.go)及[节点身份补齐](cmd/collector/node.go)。每行一条JSON，请求和响应各一条；只在当前请求可靠染色且满足解析条件时输出。有些字段使用`omitempty`，不适用或为空时会省略，**字段缺失不等于数值0或空内容**。

### 通用与协议字段

|字段|类型 / 示例|含义|
|---|---|---|
|`schema_version`|字符串，`"1"`|输出结构版本，不是HTTP版本或采集器版本|
|`source_kind`|字符串，`live_socket`|真实socket采集；`synthetic_replay`为合成回放，不代表在线业务|
|`request_id`|字符串，`live-...`|采集器生成的本观察点请求/响应配对ID；一对记录相同。不是业务`X-Request-ID`或OTel trace ID，不承诺跨节点、跨观察侧或采集重启后的全局唯一|
|`direction`|`request` / `response`|当前行是请求还是回复，与`observation_side`分开解释|
|`observation_side`|`inbound` / `outbound`|当前选中业务Pod接收调用/发起调用的观察侧；同一对请求与响应保持一致|
|`protocol`|`HTTP/1.1`、`HTTP/2`、`gRPC`|根据采集内容识别的协议；不是根据端口猜测，也不是网格外层HBONE协议名称|
|`method`|字符串，`GET` / `POST`|请求HTTP方法，主要在请求行出现；gRPC通常为POST|
|`path`|字符串，`/api/query?key=value`|请求路径，可能含查询串；gRPC通常是`/package.Service/Method`。主要在请求行出现，不等于完整域名URL|
|`status`|整数，`200` / `503`|响应HTTP状态码，主要在回复行出现。gRPC也有HTTP状态，业务RPC结果另看`grpc_status`|
|`stream_id`|整数，`1`|HTTP/2/gRPC连接内的stream ID；不同连接可能重复，不能单独用作全局请求ID；HTTP/1一般不输出|
|`headers`|对象，`{"x-debug":["enabled"]}`|当前请求或响应的初始headers；名称规范为小写，值为数组，保留重复值。HTTP/2可能含`:method`、`:path`等伪头；gRPC metadata也在此。业务`x-request-id`/`traceparent`若实际存在，则在这里|
|`trailers`|对象，值为字符串数组|已支持协议的尾部headers，主要见HTTP/2/gRPC；例如`grpc-status`、`grpc-message`。不承诺HTTP/1尾部头已同等输出|
|`body`|字符串|当前报文保留的正文前缀；HTTP/1通常按JSON文本字符串输出，HTTP/2需结合`body_encoding`；gRPC消息主要看`grpc_messages`，此字段可能为空|
|`body_encoding`|字符串，`base64`|说明正文/消息使用Base64表示；HTTP/2的`body`和gRPC的`grpc_messages`按此解释，不能将Base64本身当业务原文|
|`content_decoding`|字符串，`gzip`|当前正文/消息经过有界gzip解压；输出的是解压后保留的内容，再按`body_encoding`编码。原headers仍可能保留`content-encoding`/`grpc-encoding: gzip`，不要据此重复解压|
|`grpc_messages`|字符串数组，`["CAE="]`|gRPC消息去掉长度前缀后的protobuf字节，各项分别Base64编码；不是已解码的业务JSON。需要对应protobuf描述才能可靠还原字段，截断前缀可能无法完整解析|
|`grpc_status`|整数，`0`、`4`、`14`|gRPC响应状态；0=OK、4=DEADLINE_EXCEEDED、14=UNAVAILABLE。字段适用时即使为0也会输出；字段不存在不能当作成功|
|`truncated`|布尔值|正文、headers等输出有截断时为true。正文最多保留5120字节，headers输出预算512KiB；Base64文本可能比原字节前缀长。true不表示关闭业务连接，也不表示后续请求停止采集；false也不是端到端无丢失的保证|

headers是解析后的结构，不保留原始头名大小写、字节布局及不同头之间的线序。gRPC的HTTP `status: 200`仍可能同时有非零`grpc_status`，应按后者判断RPC结果。没有消息时`grpc_messages`可能省略；`body: ""`本身不能证明gRPC没有请求参数。

### 业务Pod与对端身份

`client`始终表示这次调用的发起端，`server`始终表示接收调用端；**响应行不会将二者对调**。`pod_*`是当前被选中的业务观察Pod，不是采集器Pod，也不是ztunnel Pod。

|字段|含义|
|---|---|
|`pod_ip`|当前业务观察Pod IP|
|`pod_name`|当前业务观察Pod名称|
|`pod_namespace`|当前业务观察Pod所在namespace|
|`pod_uid`|当前业务观察Pod UID；用于区分同名重建或IP复用的Pod代次|
|`client.ip`|调用发起端的可确认IP；不能确定时为`unknown`|
|`client.name` / `client.namespace` / `client.uid`|可可靠确认的发起端Pod身份；外部主机、代理/NAT、映射失效或歧义时为`unknown`|
|`server.ip`|调用目标IP；出站可能是Service ClusterIP，不一定是后端Pod IP|
|`server.name` / `server.namespace` / `server.uid`|可可靠确认的接收端Pod身份；仅知道Service VIP时为`unknown`，不会猜测实际后端|
|`original_destination`|出站从连接获取的原始目标`IP:port`，例如`192.0.2.10:8848`；可能是Service VIP。不可得时可为`unknown`，不适用时省略；不表示原始域名|
|`peer_identity_source`|本观察点**对端**身份的证据等级，见下表；入站对应client，出站对应server|

|`peer_identity_source`值|含义|
|---|---|
|`pod_api_verified`|连接地址与有界Pod缓存/代次检查及API复核一致，确认了对端Pod身份；不是业务认证或数据库因果证明|
|`socket_ip_only`|入站仅能确认socket源IP，无法确认对端Pod名称/UID|
|`original_destination_only`|出站仅能确认原始目标IP；常见于ClusterIP，后端身份保持unknown|
|`unknown`|无法取得可靠对端IP或Pod身份；旧版本/非node入口也可能不输出该字段|

响应沿用该对请求已确认的身份。Pod重启、IP复用、缓存失效或代理地址不能证明归属时降级为unknown，不把旧连接重新绑定为后来复用该IP的新Pod。HTTP Host和X-Forwarded-For作为headers打印，不作为后端Pod归属证据；访问外部域名时也不保证能从网络地址反向得到域名。

### inbound/outbound与请求/回复如何组合

假设业务Pod A调用业务Pod B：

|观察Pod|`observation_side`|`direction`|实际含义|身份不变|
|---|---|---|---|---|
|A|outbound|request|A向B发起请求|client=A，server=B或可确认的目标IP|
|A|outbound|response|A收到B的回复|仍client=A，server=B|
|B|inbound|request|B收到A的请求|client=A或可确认的源IP，server=B|
|B|inbound|response|B向A返回回复|仍client=A，server=B|

选`both`且两端均在范围内时，一次调用可能有两对、共四条记录。两侧`request_id`不要求相同；跨服务关联优先看实际透传的业务`x-request-id`/`traceparent`及观察点，不能只按`stream_id`或IP拼接。

例如以下是同一对出站记录的**字段节选**，实际输出还包含headers、Pod身份等字段：

```json
{"observation_side":"outbound","request_id":"live-example-1","direction":"request","protocol":"HTTP/1.1","method":"GET","path":"/api/query","body":"","truncated":false}
{"observation_side":"outbound","request_id":"live-example-1","direction":"response","protocol":"HTTP/1.1","status":200,"body":"ok","truncated":false}
```

### 诊断日志与当前未提供的字段

业务JSON写stdout，`node_waiting`、`node_capture_ready`、`node_connections_rejected`、`node_stopped protection`等诊断写stderr；`kubectl logs`可能同时展示两者，日志消费者不能把所有行都直接当业务JSON。`node_connections_rejected`表示某些连接不满足采集/解析条件，**不是采集器拒绝业务连接**。

当前记录没有独立的请求时间戳、耗时、TCP错误码或超时原因字段；Kubernetes日志时间也不是请求开始时间。若没有可靠完整的响应，不能保证输出一对，更不会伪造HTTP/gRPC失败响应。因此“没有响应记录”不能单独推断为业务超时或连接失败。

## 当前边界与参考

|范围|说明|
|---|---|
|端口|自动读取TCP containerPorts，未声明时有界发现实际监听socket；可通过Pod annotation `collector.ztunnel.io/ports`覆盖；出站不要求业务自身监听端口|
|协议/加密|HTTP/1、HTTP/2、gRPC；ztunnel网格mTLS路径已验证。Dapr自身mTLS关闭的ztunnel路径已验证；应用自身HTTPS、Dapr自身TLS、MySQL/Redis明文解密及上游因果关联不因此宣称支持|
|输出|请求头上限512KiB，正文最多打印5120字节；超过正文打印上限仍继续消费，染色gzip使用有界解压前缀；gRPC protobuf消息用base64表示|
|身份|输出观察Pod IP/name/UID/namespace；可靠时补齐对端身份，Service VIP或歧义时unknown，不猜Pod|
|数据|仅stdout，无应用结果存储；Kubernetes/内部日志平台是否落盘由环境日志策略决定|
|性能|ACK已有定向功能与500QPS长测证据；不承诺所有内部集群或1000QPS长稳已通过|

- [当前构建/部署与回退](docs/cicd.md)
- [部署源码及历史范围](docs/deployment.md)
- [验证摘要及限制](docs/validation.md)
- [Java Spring跨服务验证摘要](docs/validation.md)
- [Nacos HTTP染色验证摘要](docs/validation.md)
