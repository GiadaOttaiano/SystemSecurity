from flask import Flask, flash, render_template, request, redirect, session
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

        # Recupera il tema e il ruolo dell'utente da Vault e lo memorizza nella sessione
        role = "standard"  # Ruolo di default
        theme = "light"  # Tema di default
        url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp/{username}"
        headers = {"X-Vault-Token": session["vault_token"]}
        response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
        if response.status_code == 200:
            secret_data = response.json().get("data", {}).get("data", {})
            theme = secret_data.get("theme", "light")  # Imposta il tema salvato
            role = secret_data.get("role", "standard")  # Imposta il ruolo salvato
        session["theme"] = theme
        session["role"] = role

        return redirect("/dashboard")

    except requests.exceptions.RequestException as e:
        return f"Login failed: {e}", 401

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "vault_token" not in session:
        return redirect("/")

    # Recupera il tema e il ruolo dalla sessione
    theme = session.get("theme", "light")
    username = session["username"]
    role = session.get("role", "standard")

    # Gestisce la logica di cambio tema
    if request.method == "POST":
        new_theme = request.form.get("theme")
        try:
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp/{username}"
            headers = {"X-Vault-Token": session["vault_token"]}
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()
            secret_data = response.json().get("data", {}).get("data", {})

            # Aggiorna solo il tema
            secret_data["theme"] = new_theme
            payload = {"data": secret_data}
            response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)
            response.raise_for_status()

            # Aggiorna il tema nella sessione
            session["theme"] = new_theme
        except requests.exceptions.RequestException as e:
            return f"Failed to update theme: {e}", 500

    return render_template("dashboard.html", username=username, theme=theme, role=role)

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "vault_token" not in session:
        return redirect("/")

    # Recupera il tema e il ruolo dalla sessione
    theme = session.get("theme", "light")
    role = session.get("role", "standard")

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match!", "error")  # Messaggio di errore
            return redirect("/change-password")  # Reindirizza alla stessa pagina

        # Se l'utente è un admin, cambia la password dell'utente selezionato
        username = session["username"]
        if role == "admin":
            selected_user = request.form.get("user")  # L'admin seleziona un altro utente
        else:
            selected_user = username  # L'utente standard cambia solo la propria password

        url = f"{VAULT_ADDR}/v1/auth/userpass/users/{selected_user}/password"
        headers = {"X-Vault-Token": session["vault_token"]}
        payload = {"password": new_password}

        try:
            response = requests.post(url, json=payload, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()  # Se la richiesta è andata a buon fine

            flash("Password changed successfully!", "success")  # Messaggio di successo
            return redirect("/change-password")  # Reindirizza alla stessa pagina (mostra il messaggio di successo)

        except requests.exceptions.RequestException as e:
            flash(f"Failed to change password: {e}", "error")  # Messaggio di errore
            return redirect("/change-password")  # Reindirizza alla stessa pagina (mostra il messaggio di errore)

    # Se l'utente è un admin, mostra la lista degli utenti
    all_users = []
    if role == "admin":
        # Recupera la lista degli utenti esistenti da Vault
        url = f"{VAULT_ADDR}/v1/kv/data/secret/existing_users"
        headers = {"X-Vault-Token": session["vault_token"]}
        try:
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()
            users_data = response.json().get("data", {}).get("data", {})
            all_users = users_data.get("users", [])
        except requests.exceptions.RequestException as e:
            flash(f"Failed to retrieve users: {e}", "error")

    return render_template("change_password.html", theme=theme, role=role, all_users=all_users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    # Usa SSL direttamente nel server Flask
    context = ('Config/localhost.crt', 'Config/private_key.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)
