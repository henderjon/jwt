COVERAGEOUTFILE=coverage.out

all: test race

.PHONY: dep
dep:
	go mod vendor

.PHONY: test-vendor
test-vendor:
	go test -mod=vendor -coverprofile=$(COVERAGEOUTFILE) -covermode=count

.PHONY: test
test: dep
	go test -coverprofile=$(COVERAGEOUTFILE) -covermode=count

.PHONY: race
race: dep
	go test -race

.PHONY: test-report
test-report: test
	go tool cover -html=$(COVERAGEOUTFILE)

.PHONY: travis
travis:
	TESTSALT=86A96823-FD69-4556-8960-34887473750A
	go test -coverprofile $(COVERAGEOUTFILE) ./...
