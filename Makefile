export TESTSALT = 86A96823-FD69-4556-8960-34887473750A
export CC_TEST_REPORTER_ID = 1991acb633e90e7202a5d1fac9998f78b608f40147363199553cf70ecf5b2564
COVERAGEOUTFILE=c.out

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
	go test -coverprofile $(COVERAGEOUTFILE) ./...

.PHONY: cclimate-linux
cclimate-linux:
	curl -L https://codeclimate.com/downloads/test-reporter/test-reporter-latest-linux-amd64 > ./cc-test-reporter
	# curl -L https://codeclimate.com/downloads/test-reporter/test-reporter-latest-darwin-amd64 > ./cc-test-reporter
	chmod +x ./cc-test-reporter
	./cc-test-reporter before-build
	go test -coverprofile $(COVERAGEOUTFILE) ./...
	./cc-test-reporter after-build --exit-code $(TRAVIS_TEST_RESULT)
