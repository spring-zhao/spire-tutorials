#FROM --platform=linux/amd64 golang as builder
#WORKDIR /app
#COPY . .
#
#RUN go build -o https_client client/main.go
#RUN go build -o https_server server/main.go
#
#FROM --platform=linux/amd64 golang as base
#WORKDIR /app
#COPY --from=builder /app/https_client /app/
#COPY --from=builder /app/https_server /app/
#
#FROM --platform=linux/amd64 https_tutorials as client
#WORKDIR /app
#ENTRYPOINT ["./https_client"]
#
#FROM --platform=linux/amd64 https_tutorials as server
#WORKDIR /app
#ENTRYPOINT ["./https_server"]


# for macOS aarch-64
FROM golang as builder
WORKDIR /app
COPY . .

RUN go build -o https_client client/main.go
RUN go build -o https_server server/main.go

FROM golang as base
WORKDIR /app
COPY --from=builder /app/https_client /app/
COPY --from=builder /app/https_server /app/

FROM https_tutorials as client
WORKDIR /app
ENTRYPOINT ["./https_client"]

FROM https_tutorials as server
WORKDIR /app
ENTRYPOINT ["./https_server"]