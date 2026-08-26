.PHONY: test gates all
all: test gates
test:
	go test ./...
gates:
	./scripts/the-algorithm-comes-from-the-key.sh
	./scripts/features-are-bound.sh
	./scripts/readme-numbers.sh
