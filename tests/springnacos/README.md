# Spring HTTP与Nacos合成示例

提供Java17、Spring Boot及Nacos 2.4.3配置读取/监听示例，验证业务代码逐请求透传染色头；不提供生产部署模板。

|调用|用途|
|---|---|
|A `/demo` → B `/echo`|HTTP跨服务透传Debug-Token、X-Request-ID及重复头|
|A `/nacos-demo` → B `/nacos-echo` → Nacos HTTP配置接口|显式HTTP/OpenAPI查询逐跳染色，原SDK后台gRPC监听不染色|

`./tests/springnacos/build.sh`执行Go/Java测试并打包Linux amd64镜像。部署Chart前必须显式设置`nodeA`、`nodeB`为已批准的测试节点名，修改镜像引用并先导入相应节点，不能直接使用空值部署。

先以`javaEnabled=false`启动Nacos，再通过内部访问方式写入合成配置（dataId=`java-demo.properties`，group=`ZC_DEMO`，content=`greeting=version-two\n`），最后以`javaEnabled=true`启动A/B。按需要设置`nacosObserved=true`并将业务Pod纳入采集范围。

Nacos仅用于隔离测试：standalone/config、鉴权关闭、ClusterIP、emptyDir；不连接外部数据库，不创建公网入口。修改观察标签可能重建Pod并丢失合成配置，需重新发布配置。

有限客户端示例（替换namespace）：

```sh
kubectl -n collector-demo exec deploy/java-demo-b -- env \
  TARGET_URL=http://java-demo-a:8080/nacos-demo \
  EXPECTED_GREETING=version-two ROUND=manual CHECK_NACOS=true /app/demo-client
```

客户端200次请求、每20次一条染色；验收后停止，不是常驻压测。客户端运行在B Pod只为减少示例资源，不代表B业务递归调用A。更完整的边界见[验证摘要](../../docs/validation.md)。
