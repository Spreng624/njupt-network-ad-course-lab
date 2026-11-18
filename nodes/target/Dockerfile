FROM python:3.12-alpine
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
ARG NO_PROXY

RUN apk add --no-cache \
    bash busybox-extras iproute2 iputils openssl openssh-server \
    procps curl ca-certificates

RUN echo 'root:lab' | chpasswd
EXPOSE 22 80 443
CMD ["/bin/bash"]
