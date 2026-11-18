FROM alpine:3.20 AS detector-build
ARG APK_MIRROR=https://dl-cdn.alpinelinux.org/alpine
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
RUN sed -i "s|https://dl-cdn.alpinelinux.org/alpine|${APK_MIRROR}|g" /etc/apk/repositories \
    && apk add --no-cache gcc musl-dev libpcap-dev
COPY sniff-detector.c /src/sniff-detector.c
RUN gcc -O2 -Wall -Wextra -o /sniff-detector /src/sniff-detector.c -lpcap

FROM python:3.12-alpine
ARG APK_MIRROR=https://dl-cdn.alpinelinux.org/alpine
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
RUN sed -i "s|https://dl-cdn.alpinelinux.org/alpine|${APK_MIRROR}|g" /etc/apk/repositories \
    && apk add --no-cache \
    bash busybox-extras iproute2 iputils openssl openssh-server \
    libpcap tcpdump procps curl
COPY --from=detector-build /sniff-detector /usr/local/bin/sniff-detector
RUN echo 'root:lab' | chpasswd
CMD ["/bin/bash"]
