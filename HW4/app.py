from flask import Flask, render_template, request, redirect, session, jsonify
import requests

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Cambia con una chiave sicura

VAULT_ADDR = "https://127.0.0.1:8200"  # Indirizzo del tuo server Vault
VAULT_VERIFY = False  # Disabilita la verifica del certificato per test locali

@app.route("/")
def index():
    if "vault_token" in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # Autenticazione con Vault
    url = f"{VAULT_ADDR}/v1/auth/userpass/login/{username}"
    payload = {"password": password}
    try:
        response = requests.post(url, json=payload, verify=VAULT_VERIFY)
        response.raise_for_status()

        data = response.json()
        session["vault_token"] = data["auth"]["client_token"]
        session["username"] = username
        return redirect("/dashboard")

    except requests.exceptions.RequestException as e:
        return f"Login failed: {e}", 401

@app.route("/dashboard")
def dashboard():
    if "vault_token" not in session:
        return redirect("/")

    # Accesso a un segreto specifico su Vault
    username = session["username"]
    url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp/{username}"
    headers = {"X-Vault-Token": session["vault_token"]}

    try:
        # Fai la richiesta per ottenere il segreto
        response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
        
        # Stampa il codice di stato per il debug
        print(f"Vault Response Status Code: {response.status_code}")  # Debug
        response.raise_for_status()

        # Stampa la risposta JSON per il debug
        print(f"Vault Response JSON: {response.json()}")  # Debug

        secret_data = response.json().get("data", {}).get("data", {})
        
        if not secret_data:
            print(f"Error: No secret data found for {username}")  # Debug
        
        return render_template("dashboard.html", username=username, secret=secret_data)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")  # Debug
        return f"Failed to retrieve secrets: {e}", 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, ssl_context=("Config/localhost.crt", "Config/private_key.key"))
