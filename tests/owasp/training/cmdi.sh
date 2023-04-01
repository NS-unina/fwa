
fwa="poetry run fwa"

PAYLOAD_PATH=../payloads/cmdi.csv
CMDI_OWASP="owasp-cmdi"
$fwa fuzz ${CMDI_OWASP} --payload-file=${PAYLOAD_PATH} 
# --querystring

# # Generate an observations.csv file
$fwa analyze ${CMDI_OWASP} fwa-${CMDI_OWASP} $PAYLOAD_PATH
$fwa oracle observations.csv