#!/bin/bash
export fwa="poetry run fwa"

$fwa replay wavsep-sql-get-500-error  --proxy 127.0.0.1:8082
$fwa replay wavsep-sql-get-200-difference --proxy 127.0.0.1:8082
$fwa replay wavsep-sql-get-200-equal --proxy 127.0.0.1:8082
$fwa replay wavsep-sql-get-200-error --proxy 127.0.0.1:8082
$fwa replay wavsep-sql-get-500-error --proxy 127.0.0.1:8082

