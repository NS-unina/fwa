#!/bin/bash
export fwa="poetry run fwa"

$fwa replay wavsep-lfi-get-200-differentiation --proxy 127.0.0.1:8082
$fwa replay wavsep-lfi-get-200-error --proxy 127.0.0.1:8082
$fwa replay wavsep-lfi-get-302-redirect --proxy 127.0.0.1:8082
$fwa replay wavsep-lfi-get-404-error --proxy 127.0.0.1:8082
$fwa replay wavsep-lfi-get-500-error --proxy 127.0.0.1:8082
