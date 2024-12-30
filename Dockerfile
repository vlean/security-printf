FROM docker.io/library/golang:1.18 as builder

COPY / /securityprintf
WORKDIR /securityprintf
RUN CGO_ENABLED=0 make

FROM docker.io/library/golang:1.18
COPY --from=builder /securityprintf/securityprintf /usr/bin/
CMD ["securityprintf"]
