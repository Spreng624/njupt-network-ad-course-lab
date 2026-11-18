FROM alpine:3.20
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy

RUN apk add --no-cache bash iproute2 iptables iputils procps
CMD ["/bin/bash"]
