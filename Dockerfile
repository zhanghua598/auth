# Start with a base image containing Java runtime
#FROM openjdk:8-jdk-alpine
FROM registry.cn-chengdu.aliyuncs.com/zhangh/jdk8

# Add Maintainer Info
MAINTAINER Bing <zhangh1113@gmail.com>

# Set Env
ENV TZ Asia/chengdu

# The application's jar file
ARG JAR_FILE=target/auth-0.0.1-SNAPSHOT.jar

# Add the application's jar to the container
ADD ${JAR_FILE} app.jar

# Run the jar file
ENTRYPOINT ["java","-jar","/app.jar"]