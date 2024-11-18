# Permesso per effettuare il login
path "auth/userpass/login/*" {
  capabilities = ["create", "read"]
}

# Permesso per leggere i segreti
path "kv/data/secret/webapp/*" {
  capabilities = ["read", "update"]
}

# Permesso per cambiare la password
path "auth/userpass/users/{{identity.entity.aliases.auth_userpass_893f37f9.name}/password}" {
  capabilities = ["update"]
  allowed_parameters = {    
    "password" = []
  }
}
