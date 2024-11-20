from flask import Flask, flash, render_template, request, redirect, session  # Importa Flask e funzioni per sessioni, template e messaggi flash
import requests  # Libreria per effettuare richieste HTTP
import secrets  # Libreria per generare valori casuali sicuri

app = Flask(__name__)  # Crea un'applicazione Flask
# Genera una chiave segreta casuale di 32 byte per proteggere le sessioni
app.secret_key = secrets.token_hex(32)

VAULT_ADDR = "https://127.0.0.1:8200"  # Indirizzo del server Vault
VAULT_VERIFY = False  # Disabilita la verifica del certificato per test locali

@app.route("/")  # Rotta principale (homepage)
def index():
    if "vault_token" in session:  # Controlla se esiste un token nella sessione
        return redirect("/dashboard")  # Se sì, reindirizza al dashboard
    return render_template("login.html")  # Altrimenti, mostra la pagina di login

@app.route("/login", methods=["POST"])  # Rotta per il login, accetta solo POST
def login():
    username = request.form.get("username")  # Ottiene il nome utente dal form
    password = request.form.get("password")  # Ottiene la password dal form

    # URL per autenticazione con Vault
    url = f"{VAULT_ADDR}/v1/auth/userpass/login/{username}"
    payload = {"password": password}  # Payload per la richiesta
    try:
        # Effettua una richiesta POST per autenticarsi con Vault
        response = requests.post(url, json=payload, verify=VAULT_VERIFY)
        response.raise_for_status()  # Genera un'eccezione se la risposta non è 200 OK

        data = response.json()  # Decodifica la risposta JSON
        session["vault_token"] = data["auth"]["client_token"]  # Salva il token nella sessione
        session["username"] = username  # Salva il nome utente nella sessione

        # Recupera il tema e il ruolo dell'utente da Vault
        role = "standard"  # Ruolo di default
        theme = "light"  # Tema di default
        url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp/{username}"  # URL per accedere ai segreti utente
        headers = {"X-Vault-Token": session["vault_token"]}  # Intestazioni con il token
        response = requests.get(url, headers=headers, verify=VAULT_VERIFY)  # Effettua la richiesta GET a Vault
        if response.status_code == 200:  # Se la richiesta ha successo
            secret_data = response.json().get("data", {}).get("data", {})  # Estrae i dati
            theme = secret_data.get("theme", "light")  # Ottiene il tema, se disponibile
            role = secret_data.get("role", "standard")  # Ottiene il ruolo, se disponibile
        session["theme"] = theme  # Salva il tema nella sessione
        session["role"] = role  # Salva il ruolo nella sessione

        return redirect("/dashboard")  # Reindirizza al dashboard

    except requests.exceptions.RequestException:  # Gestisce errori nelle richieste HTTP
        flash("Invalid credentials. Please try again.", "error")  # Mostra un messaggio di errore
        return redirect("/")  # Torna alla pagina di login

@app.route("/dashboard", methods=["GET", "POST"])  # Rotta per il dashboard, supporta GET e POST
def dashboard():
    if "vault_token" not in session:  # Controlla se l'utente è autenticato
        return redirect("/")  # Se no, reindirizza al login

    # Recupera il tema e il ruolo dalla sessione
    theme = session.get("theme", "light")
    username = session["username"]
    role = session.get("role", "standard")

    # Gestisce il cambio tema tramite POST
    if request.method == "POST":
        new_theme = request.form.get("theme")  # Ottiene il nuovo tema dal form
        try:
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp/{username}"  # URL per accedere ai segreti utente
            headers = {"X-Vault-Token": session["vault_token"]}  # Intestazioni con il token
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)  # Richiesta GET
            response.raise_for_status()
            secret_data = response.json().get("data", {}).get("data", {})  # Estrae i dati

            # Aggiorna solo il tema
            secret_data["theme"] = new_theme
            payload = {"data": secret_data}  # Prepara i dati aggiornati
            response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)  # Richiesta POST per aggiornare Vault
            response.raise_for_status()

            session["theme"] = new_theme  # Aggiorna il tema nella sessione
        except requests.exceptions.RequestException as e:  # Gestisce errori HTTP
            return f"Failed to update theme: {e}", 500  # Ritorna un errore

    return render_template("dashboard.html", username=username, theme=theme, role=role)  # Mostra il dashboard

@app.route("/account-settings", methods=["GET", "POST"])  # Rotta per le impostazioni dell'account
def account_settings():
    if "vault_token" not in session:  # Controlla se l'utente è autenticato
        return redirect("/")  # Se no, reindirizza al login

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")

    if request.method == "POST":  # Gestisce aggiornamenti tramite POST
        new_theme = request.form.get("theme")  # Ottiene il nuovo tema
        try:
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp/{username}"  # URL per i segreti utente
            headers = {"X-Vault-Token": session["vault_token"]}  # Intestazioni con il token
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)  # Richiesta GET
            response.raise_for_status()

            secret_data = response.json().get("data", {}).get("data", {})  # Estrae i dati
            secret_data["theme"] = new_theme  # Aggiorna il tema
            payload = {"data": secret_data}  # Prepara i dati aggiornati

            response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)  # Richiesta POST per aggiornare Vault
            response.raise_for_status()

            session["theme"] = new_theme  # Aggiorna il tema nella sessione
            flash("Theme updated successfully!", "success")  # Messaggio di successo
        except requests.exceptions.RequestException as e:  # Gestisce errori HTTP
            flash(f"Failed to update theme: {e}", "error")  # Messaggio di errore

    return render_template("account_settings.html", username=username, role=role, theme=theme)  # Mostra le impostazioni

@app.route("/change-password", methods=["GET", "POST"])  # Rotta per cambiare la password
def change_password():
    if "vault_token" not in session:  # Controlla se l'utente è autenticato
        return redirect("/")  # Se no, reindirizza al login

    theme = session.get("theme", "light")  # Recupera il tema dalla sessione
    role = session.get("role", "standard")  # Recupera il ruolo dalla sessione

    if request.method == "POST":  # Gestisce aggiornamenti tramite POST
        new_password = request.form.get("new_password")  # Nuova password
        confirm_password = request.form.get("confirm_password")  # Conferma password

        if new_password != confirm_password:  # Controlla se le password coincidono
            flash("Passwords do not match!", "error")  # Messaggio di errore
            return redirect("/change-password")  # Reindirizza alla stessa pagina

        username = session["username"]
        if role == "admin":  # Se l'utente è un admin
            selected_user = request.form.get("user")  # L'admin può selezionare un utente
        else:
            selected_user = username  # L'utente standard cambia solo la propria password

        url = f"{VAULT_ADDR}/v1/auth/userpass/users/{selected_user}/password"  # URL per cambiare la password
        headers = {"X-Vault-Token": session["vault_token"]}  # Intestazioni con il token
        payload = {"password": new_password}  # Payload con la nuova password

        try:
            response = requests.post(url, json=payload, headers=headers, verify=VAULT_VERIFY)  # Richiesta POST per aggiornare Vault
            response.raise_for_status()  # Verifica successo della richiesta

            flash("Password changed successfully!", "success")  # Messaggio di successo
            return redirect("/change-password")  # Reindirizza alla stessa pagina
        except requests.exceptions.RequestException as e:  # Gestisce errori HTTP
            flash(f"Failed to change password: {e}", "error")  # Messaggio di errore
            return redirect("/change-password")  # Reindirizza alla stessa pagina

    all_users = []  # Inizializza la lista utenti
    if role == "admin":  # Se l'utente è un admin
        url = f"{VAULT_ADDR}/v1/kv/data/secret/existing_users"  # URL per gli utenti esistenti
        headers = {"X-Vault-Token": session["vault_token"]}  # Intestazioni con il token
        try:
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)  # Richiesta GET
            response.raise_for_status()
            users_data = response.json().get("data", {}).get("data", {})  # Estrae i dati
            all_users = users_data.get("users", [])  # Ottiene la lista utenti
        except requests.exceptions.RequestException as e:  # Gestisce errori HTTP
            flash(f"Failed to retrieve users: {e}", "error")  # Messaggio di errore

    return render_template("change_password.html", theme=theme, role=role, all_users=all_users)  # Mostra la pagina di cambio password

@app.route("/logout")  # Rotta per il logout
def logout():
    session.clear()  # Cancella tutti i dati dalla sessione
    return redirect("/")  # Reindirizza alla pagina di login

if __name__ == "__main__":  
    context = ('Config/localhost.crt', 'Config/private_key.key')  # Percorsi al certificato e chiave privata SSL
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)  # Avvia il server Flask con supporto SSL
