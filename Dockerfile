FROM golang:latest AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" CGO_ENABLED=0 go build -ldflags "-s -w" -o ca-portal


FROM alpine:latest

RUN apk --no-cache add libcap

COPY --from=builder /app/ca-portal /bin/
RUN setcap 'cap_net_bind_service=+ep' /bin/ca-portal

USER 1000

CMD ["/bin/ca-portal"]
