# Accesso completo a tutti i percorsi
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Accesso per gestione utenti in auth/userpass
path "auth/userpass/users/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Accesso per gestire le policy
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Accesso ai token
path "auth/token/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Accesso al motore dei segreti
path "kv/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Accesso ai comandi di sistema
path "sys/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
