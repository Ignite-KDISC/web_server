FROM golang:1.24-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy application files
COPY . .

RUN go build -o main .

EXPOSE 8080

# Start the application
CMD ["/app/main"]
