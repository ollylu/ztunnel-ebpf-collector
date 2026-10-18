FROM eclipse-temurin:17-jre-jammy@sha256:b3054a20e1a851574cdb1692dd0db5310c647e62214a2a7abecbec1b9e3ae8f1
WORKDIR /app
COPY target/spring-nacos-demo-0.1.0.jar /app/demo.jar
COPY target/demo-client /app/demo-client
USER 10001:10001
ENTRYPOINT ["java", "-jar", "/app/demo.jar"]
