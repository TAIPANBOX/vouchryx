.PHONY: test gates all
all: test gates
test:
	go test ./...
gates:
	./scripts/features-are-bound.sh
	./scripts/readme-numbers.sh
