#!/bin/bash

fwa="poetry run fwa"

PAYLOAD_PATH=../payloads/xss.csv
SESSION=owasp-xss
$fwa fuzz $SESSION --payload-file=${PAYLOAD_PATH} --querystring --body

# # Generate an observations.csv file
# $fwa analyze owasp-sqli fwa-owasp-sqli $PAYLOAD_PATH
# $fwa oracle observations.csv



# REDUCED
# $fwa fuzz reduced-owasp-sqli --payload-file=${PAYLOAD_PATH} 
# 
# # Generate an observations.csv file
# $fwa analyze reduced-owasp-sqli fwa-reduced-owasp-sqli $PAYLOAD_PATH
# $fwa oracle observations.csv