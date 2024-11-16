from flask import Flask, render_template, request, redirect, session
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
        response.raise_for_status()

        secret_data = response.json().get("data", {}).get("data", {})
        return render_template("dashboard.html", username=username, secret=secret_data)

    except requests.exceptions.RequestException as e:
        return f"Failed to retrieve secrets: {e}", 500

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "vault_token" not in session:
        return redirect("/")

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            return "Passwords do not match!", 400

        # Cambia la password su Vault
        username = session["username"]
        url = f"{VAULT_ADDR}/v1/auth/userpass/users/{username}/password"
        headers = {"X-Vault-Token": session["vault_token"]}
        payload = {"password": new_password}

        try:
            response = requests.post(url, json=payload, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()
            return "Password changed successfully!", 200
        except requests.exceptions.RequestException as e:
            return f"Failed to change password: {e}", 500

    return render_template("change_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    # Usa SSL direttamente nel server Flask
    context = ('Config/localhost.crt', 'Config/private_key.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)
