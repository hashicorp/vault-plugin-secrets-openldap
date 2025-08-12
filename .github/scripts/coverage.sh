#!/bin/bash
#
# * Generates `coverage/index.html`: HTML artifact for download,
# * Generates `coverage/report.xml`: report of failed tests in Junit format, and
# * Validates the minimum code coverage still applies.
#
# Depends on:
# * github.com/jstemmer/go-junit-report
# * github.com/wadey/gocovmerge
EXPECTED_COVERAGE=80

set -o nounset
shopt -s extglob

TESTS_FAILED=0

RED=$(printf "\e[31m")
GREEN=$(printf "\e[32m")
RESET=$(printf "\e[m")

printf_green() {
  printf "${GREEN}$*${RESET}\n"
}

printf_red() {
  printf "${RED}$*${RESET}\n"
}

cover_code() {
  for pkg in $(go list ./...); do
    go test -v -coverprofile coverage/profile_${pkg//+([\.\/])/_} $pkg 2>&1 > coverage/pkg
    if [ $? -ne 0 ]; then
      TESTS_FAILED=1
      printf_red $pkg
      cat coverage/pkg
    else
      COVERAGE=`tail -n 1 coverage/pkg | grep -o -E '[0-9]{1,3}\.[0-9]{1,2}' | tail -n 1`
      printf "${GREEN}%-135s %s${RESET}\n" $pkg $COVERAGE
    fi

    cat coverage/pkg >> coverage/test_output
  done
}

gen_coverage_report() {
  gocovmerge coverage/profile_* > coverage/all_profiles_merged
  go tool cover -html=coverage/all_profiles_merged -o coverage/index.html
  go tool cover -func=coverage/all_profiles_merged > coverage_output

  cat coverage/test_output | go-junit-report > coverage/report.xml

  COVERAGE=`tail -n 1 coverage_output | grep -o -E '[0-9]{1,3}' | head -n 1`
  if [ "$COVERAGE" -lt "$EXPECTED_COVERAGE" ]; then
    printf "coverage is ${RED}%s%%${RESET}, that is less than expected ${GREEN}%s%%${RESET}\n" $COVERAGE $EXPECTED_COVERAGE
    TESTS_FAILED=1
  fi

  tail -n 1 coverage_output
}

rm -rf coverage/ || true
mkdir -p coverage/

go install github.com/jstemmer/go-junit-report/v2@latest
go install github.com/wadey/gocovmerge@latest

cover_code
gen_coverage_report

exit $TESTS_FAILED
