#!/bin/bash -i
fwa="poetry run fwa"

PAYLOAD_PATH=../payloads/sqli.csv
# $fwa fuzz owasp-sqli --payload-file=${PAYLOAD_PATH} --querystring --body
$fwa analyze owasp-sqli fwa-owasp-sqli $PAYLOAD_PATH