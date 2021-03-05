FROM maven:3.6.3-jdk-11

COPY pom.xml /service/pom.xml
COPY src/ /service/src

WORKDIR /service/

ARG m2

RUN mkdir -p ~/.m2
RUN echo ${m2} > ~/.m2/settings.xml
RUN mvn package
RUN rm ~/.m2/settings.xml


EXPOSE 8080

ENTRYPOINT [ "java", "-jar", "target/gateway-1.0-SNAPSHOT.jar" ]