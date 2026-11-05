FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /inspector .
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /inspector /inspector
USER 65532:65532
ENTRYPOINT ["/inspector"]
