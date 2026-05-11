#!/bin/bash
export fwa="poetry run fwa"

# XSS 
# $fwa fuzz wavsep-xss-get --payload-file xss.csv --querystring
# $fwa analyze wavsep-xss-get fwa-wavsep-xss-get xss.csv
# $fwa oracle observations.csv


# SQL
# $fwa fuzz wavsep-sql-get-200-error --payload-file sqli.csv --querystring
$fwa analyze wavsep-sql-get-200-error fwa-wavsep-sql-get-200-error sqli.csv
$fwa oracle observations.csv


# XSS Case 6
# $fwa fuzz case6 --payload-file case6.csv --querystring
# $fwa analyze case6 fwa-case6 case6.csv
# $fwa oracle observations.csv