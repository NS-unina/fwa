
fwa="poetry run fwa"

PAYLOAD_PATH=../payloads/lfi.csv
LFI_OWASP="owasp-lfi"
$fwa fuzz ${LFI_OWASP} --payload-file=${PAYLOAD_PATH} 

# # Generate an observations.csv file
$fwa analyze ${LFI_OWASP} fwa-${LFI_OWASP} $PAYLOAD_PATH
$fwa oracle observations.csv