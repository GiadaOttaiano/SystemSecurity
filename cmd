vault server -config="C:/Program Files/Vault_1.18.1/config/vault-config.hcl"
slapd.exe -f C:\OpenLDAP\slapd.conf -h "ldaps://localhost:636" -d 256
httpd.exe

pP9Wirfr/syrJlS2Sv7gURZBwRk888rDNLZ4oHfRc48F
R5lHmSvf1E9PPeHX19dj+82A7u1KyxL6T1R1brJMF9EL
AKexKiU8nE0gNOMb+tF3W1lByISoT2JNSP/JE0x2Amon

hvs.xvHUkV2aVM62VmntIX5KTipi

set VAULT_ADDR=https://127.0.0.1:8200
set VAULT_SKIP_VERIFY=true
vault audit enable file file_path=/var/log/vault_audit.log