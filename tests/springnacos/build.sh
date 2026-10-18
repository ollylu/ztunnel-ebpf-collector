#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
CGO_ENABLED=0 go test ./tests/springnacosclient
docker run --rm -v "$PWD/tests/springnacos:/work" -v zc-i20-maven-cache:/root/.m2 -w /work maven:3.9.9-eclipse-temurin-17@sha256:f58d59b6273e785ac0a4477f6e9b5ba1d7731c75b906c0f7b34076f1851318cc mvn -B -ntp package
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o tests/springnacos/target/demo-client ./tests/springnacosclient
revision=$(git rev-parse HEAD)
docker build --platform linux/amd64 -f tests/springnacos/Dockerfile -t "ztunnel-spring-nacos:$revision" tests/springnacos
helm lint tests/springnacos/chart
