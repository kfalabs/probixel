#!/bin/bash
# Quick Docker commands for Probixel

# Build the image
build() {
    docker build -t probixel:latest -f "$(dirname "$0")/Dockerfile" .
}

# Run with docker-compose
up() {
    docker-compose -f "$(dirname "$0")/docker-compose.example.yml" up -d
}

# Stop docker-compose
down() {
    docker-compose -f "$(dirname "$0")/docker-compose.example.yml" down
}

# View logs
logs() {
    if docker-compose -f "$(dirname "$0")/docker-compose.example.yml" ps | grep -q probixel; then
        docker-compose -f "$(dirname "$0")/docker-compose.example.yml" logs -f probixel
    else
        docker logs -f probixel
    fi
}

# Restart the container
restart() {
    if docker-compose -f "$(dirname "$0")/docker-compose.example.yml" ps | grep -q probixel; then
        docker-compose -f "$(dirname "$0")/docker-compose.example.yml" restart probixel
    else
        docker restart probixel
    fi
}

# Run with Docker CLI
run() {
    if [ ! -f config.yaml ]; then
        echo "Error: config.yaml not found. Copy config.example.yaml to config.yaml first."
        exit 1
    fi
    
    docker run -d \
        --name probixel \
        -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
        --restart unless-stopped \
        probixel:latest
}

# Stop and remove container
stop() {
    docker stop probixel
    docker rm probixel
}

# Shell into running container (for debugging)
shell() {
    docker exec -it probixel /bin/sh
}

# Show container stats
stats() {
    docker stats probixel --no-stream
}

# Show image size
size() {
    docker images probixel:latest
}

# Clean up old images
clean() {
    docker image prune -f
}

# Show help
help() {
    echo "Probixel Docker Helper Script"
    echo ""
    echo "Usage: ./docker.sh [command]"
    echo ""
    echo "Commands:"
    echo "  build    - Build the Docker image"
    echo "  run      - Run container with Docker CLI"
    echo "  up       - Start with docker-compose"
    echo "  down     - Stop docker-compose"
    echo "  logs     - View container logs"
    echo "  restart  - Restart the container"
    echo "  stop     - Stop and remove container"
    echo "  shell    - Open shell in running container"
    echo "  stats    - Show container resource usage"
    echo "  size     - Show image size"
    echo "  clean    - Remove unused Docker images"
    echo "  help     - Show this help message"
}

# Main
case "$1" in
    build)
        build
        ;;
    run)
        run
        ;;
    up)
        up
        ;;
    down)
        down
        ;;
    logs)
        logs
        ;;
    restart)
        restart
        ;;
    stop)
        stop
        ;;
    shell)
        shell
        ;;
    stats)
        stats
        ;;
    size)
        size
        ;;
    clean)
        clean
        ;;
    help|*)
        help
        ;;
esac
