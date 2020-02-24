FROM gradle:6.1.1-jdk13 AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle shadowJar --no-daemon

FROM openjdk:13.0-jdk-slim
RUN mkdir /app
RUN apt-get update
RUN apt-get install -y libsodium-dev libsodium23
COPY --from=build /home/gradle/src/build/libs/nstp-cert-status-server.jar /app/nstp-cert-status-server.jar
ENTRYPOINT ["java", "-server" ,"-jar","/app/nstp-cert-status-server.jar"]