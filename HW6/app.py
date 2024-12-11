from flask import Flask, flash, render_template, request, redirect, session
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
import secrets
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from keycloak import KeycloakOpenID
import logging
import vakt
from vakt.rules import Eq, StartsWith, And, Greater, Less, Any
import jwt

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Abilita la modalità proxy per Flask
app.wsgi_app = ProxyFix(app.wsgi_app)

logging.basicConfig(level=logging.DEBUG)
VAULT_ADDR = "https://127.0.0.1:8200"
VAULT_VERIFY = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Definisci la policy in VAKT
policy = vakt.Policy(
    123456,
    actions=[Eq('modify')],
    resources=[StartsWith('note')],
    subjects=[{'username': Any()}],  # L'utente può essere qualsiasi
    effect=vakt.ALLOW_ACCESS,
    context={'current_time': And(Greater('09:00:00'), Less('22:00:00'))},
    description="""Consenti la modifica delle note solo tra le 9:00 e le 18:00"""
)

# Memorizza la policy in VAKT
storage = vakt.MemoryStorage()
storage.add(policy)
guard = vakt.Guard(storage, vakt.RulesChecker())

# Configurazione Keycloak
KEYCLOAK_SERVER_URL = "http://localhost:8081/"
REALM_NAME = "Webapp"
CLIENT_ID = "webapp-client"
CLIENT_SECRET = "o5xvJpXeZhP8FHW3RU8YEQuvsKRjO2Hi"

# Keycloak OpenID Connect client
keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=CLIENT_ID,
    client_secret_key=CLIENT_SECRET,
    realm_name=REALM_NAME,
    verify=False
)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<Note {self.id} - {self.username}>"
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.id} - {self.username}>"

with app.app_context():
    db.create_all()

@app.route("/")
def index():
    if "access_token" in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/login-keycloak")
def login_keycloak():
    # Redirige l'utente al provider Keycloak per l'autenticazione
    redirect_uri = "https://localhost:443/callback"
    auth_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/auth"
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid email profile"
    }
    auth_request_url = f"{auth_url}?{requests.compat.urlencode(params)}"
    return redirect(auth_request_url)

# Decodifica il token JWT e ottieni i ruoli
def get_roles_from_token(token):
    try:
        # Decodifica il token JWT senza verificarne la firma
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        return decoded_token.get("realm_access", {}).get("roles", [])
    except jwt.ExpiredSignatureError:
        return []
    except jwt.DecodeError:
        return []
    
def get_sub_from_token(token):
    try:
        # Decodifica il token JWT senza verificarne la firma
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        return decoded_token.get("sub")  # Restituisce il campo "sub"
    except jwt.ExpiredSignatureError:
        return None  # Restituisce None se il token è scaduto
    except jwt.DecodeError:
        return None  # Restituisce None se c'è un errore nel decodificare il token

@app.route("/callback")
def callback():
    code = request.args.get("code")     # Authorization Code fornito da Keycloak
    if not code:
        flash("Codice di autorizzazione non ricevuto.", "error")
        return redirect("/")

    token_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/token"
    redirect_uri = "https://localhost:443/callback"

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }

    try:
        response = requests.post(token_url, data=data, verify=False)
        response.raise_for_status()

        token_data = response.json()
        session["access_token"] = token_data["access_token"]
        session["refresh_token"] = token_data["refresh_token"]
        
        logging.debug(f"Access Token: {token_data['access_token']}")
        print("Access Token:", token_data["access_token"])

        # Decodifica il token per ottenere informazioni sul ruolo
        roles = get_roles_from_token(token_data["access_token"])
        session["roles"] = roles
        
        print("Info session:", session["roles"])
        
        # Recupera informazioni sull'utente
        userinfo_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/userinfo"
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        user_info = requests.get(userinfo_url, headers=headers, verify=False).json()

        session["username"] = user_info["preferred_username"]

        # Usa direttamente il token di Keycloak come token Vault
        session["vault_token"] =  get_sub_from_token(token_data["access_token"])
        print(f"Vault Token in session: {session.get('vault_token')}")

        return redirect("/dashboard")
    except requests.exceptions.RequestException as e:
        logging.error(f"Errore durante l'autenticazione con Keycloak: {e}")
        flash("Errore durante l'autenticazione.", "error")
        return redirect("/")

def get_vault_secret(path):
    try:
        url = f"{VAULT_ADDR}/v1/kv/data/{path}"
        headers = {"X-Vault-Token": session["vault_token"]}
        response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
        response.raise_for_status()
        return response.json().get("data", {}).get("data", {})
    except requests.RequestException as e:
        logging.error(f"Errore nel recupero del segreto Vault: {e}")
        return None

@app.route("/admin_page")
def admin_page():
    if "access_token" not in session:
        return redirect("/")

    # Controlla se l'utente ha il ruolo 'admin'
    roles = session.get("roles", [])
    if "admin" in roles:
        return render_template("admin_page.html")
    else:
        flash("Accesso negato: non hai i permessi per vedere questa pagina.", "error")
        return redirect("/dashboard")

@app.route("/logout")
def logout():
    try:
        if "access_token" in session:
            keycloak_openid.logout(session["refresh_token"])
    except Exception:
        pass
    session.clear()
    return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "access_token" not in session:
        return redirect("/")

    theme = session.get("theme", "light")
    username = session["username"]
    role = session.get("roles", "standard")

    if request.method == "POST":
        new_theme = request.form.get("theme")
        try:
            secret_path = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
            secret_data = get_vault_secret(secret_path)
            if not secret_data:
                flash("Impossibile accedere ai dati su Vault.", "error")
                return redirect("/dashboard")

            secret_data["theme"] = new_theme  # Solo cambia il tema

            # Aggiorna i dati su Vault
            headers = {"X-Vault-Token": session["vault_token"]}
            payload = {"data": secret_data}
            url = f"{VAULT_ADDR}/v1/kv/data/{secret_path}"
            response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)
            response.raise_for_status()

            session["theme"] = new_theme
            flash("Tema aggiornato con successo!", "success")
        except requests.exceptions.RequestException as e:
            flash(f"Errore durante l'aggiornamento del tema: {e}", "error")

    return render_template("dashboard.html", username=username, theme=theme, role=role)


@app.route("/account-settings", methods=["GET", "POST"])  # Rotta per le impostazioni dell'account
def account_settings():
    if "access_token" not in session:  # Controlla se l'utente è autenticato
        return redirect("/")  # Se no, reindirizza al login

    username = session["username"]
    
    roles = session.get("roles", [])
    
    if "admin" in roles:
        role = "admin"
    else:
        role = "standard"
        
    theme = session.get("theme", "light")

    if request.method == "POST":  # Gestisce aggiornamenti tramite POST
        new_theme = request.form.get("theme")  # Ottiene il nuovo tema
        print("tema" + new_theme)
        try:
            print("vault token account settings" + session["vault_token"])
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"  # URL per i segreti utente
            headers = {"X-Vault-Token": session["vault_token"]}  # Intestazioni con il token
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)  # Richiesta GET
            response.raise_for_status()
            print("risposta:" + response.text)

            secret_data = response.json().get("data", {}).get("data", {})  # Estrae i dati
            secret_data["theme"] = new_theme  # Aggiorna il tema
            payload = {"data": secret_data}  # Prepara i dati aggiornati

            response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)  # Richiesta POST per aggiornare Vault
            response.raise_for_status()

            session["theme"] = new_theme  # Aggiorna il tema nella sessione
            flash("Tema modificato con successo!", "success")  # Messaggio di successo
        except requests.exceptions.RequestException as e:  # Gestisce errori HTTP
            flash(f"Failed to update theme: {e}", "error")  # Messaggio di errore
            print(f"Vault response error: {response.text}")  # Mostra l'intero contenuto di errore

    return render_template("account_settings.html", username=username, role=role, theme=theme)  # Mostra le impostazioni

@app.route("/notifications")
def notifications():
    if "access_token" not in session:
        return redirect("/")

    username = session["username"]
    theme = session.get("theme", "light")
    
    # Ottieni le notifiche dell'utente
    user_notifications = Notification.query.filter_by(username=username).order_by(Notification.timestamp.desc()).all()
    return render_template("notifications.html", notifications=user_notifications, theme=theme)

@app.route("/notifications/clear-all", methods=["POST"])
def clear_all_notifications():
    if "username" not in session:
        return redirect("/")
    
    username = session["username"]
    # Elimina tutte le notifiche dell'utente
    Notification.query.filter_by(username=username).delete()
    db.session.commit()
    flash("Tutte le notifiche sono state eliminate.", "success")
    return redirect("/notifications")

@app.route("/notifications/delete/<int:id>", methods=["POST"])
def delete_notification(id):
    if "username" not in session:
        return redirect("/")

    # Recupera la notifica per l'ID fornito
    notification = Notification.query.get(id)
    if notification:
        db.session.delete(notification)
        db.session.commit()
        flash("Notifica eliminata.", "success")
    else:
        flash("Notifica non trovata.", "error")
    
    return redirect("/notifications")

@app.route("/notes")
def notes():
    if "access_token" not in session:
        return redirect("/")

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")

    if role == "admin" or role == "manager":
        all_notes = Note.query.all()
    else:
        all_notes = Note.query.filter_by(username=username).all()

    return render_template("notes.html", notes=all_notes, theme=theme)

@app.route("/add-note", methods=["GET", "POST"])
def add_note():
    if "access_token" not in session:
        return redirect("/")

    role = session.get("role", "standard")
    theme = session.get("theme", "light")

    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        # Crea l'inquiry per VAKT
        inquiry = vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )

        # Verifica se l'accesso è permesso
        if guard.is_allowed(inquiry):
            content = request.form.get("content")
            username = session["username"]
            if content:
                new_note = Note(content=content, username=username, role=role)
                db.session.add(new_note)
                db.session.commit()
                flash("Nota aggiunta con successo!", "success")
                return redirect("/notes")
        else:
            flash("Non hai i permessi per aggiungere una nota in questo momento.", "error")

    return render_template("add_note.html", role=role, theme=theme)

@app.route("/edit-note/<int:id>", methods=["GET", "POST"])
def edit_note(id):
    if "access_token" not in session:
        return redirect("/")

    note = Note.query.get_or_404(id)
    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")

    if note.username != username and role != "admin":
        flash("Non hai i permessi per modificare questa nota.", "error")
        return redirect("/notes")

    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        # Crea l'inquiry per VAKT
        inquiry = vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )

        # Verifica se l'accesso è permesso
        if guard.is_allowed(inquiry):
            new_content = request.form.get("content")
            if new_content:
                note.content = new_content
                db.session.commit()
                flash("Nota modificata con successo!", "success")
                return redirect("/notes")
        else:
            flash("Non hai i permessi per modificare questa nota in questo momento.", "error")

    return render_template("edit_note.html", note=note, theme=theme)

@app.route("/delete-note/<int:id>", methods=["POST"])
def delete_note(id):
    if "access_token" not in session:
        return redirect("/")

    note = Note.query.get_or_404(id)
    username = session["username"]
    role = session.get("role", "standard")

    if note.username != username and role != "admin":
        flash("Non hai i permessi per eliminare questa nota.", "error")
        return redirect("/notes")

    current_time = datetime.now().strftime("%H:%M:%S")
    # Crea l'inquiry per VAKT
    inquiry = vakt.Inquiry(
        action='modify',
        resource='note',
        subject={'username': session['username']},
        context={'current_time': current_time}
    )

    # Verifica se l'accesso è permesso
    if guard.is_allowed(inquiry):
        db.session.delete(note)
        db.session.commit()
        flash("Nota eliminata con successo!", "success")
    else:
        flash("Non hai i permessi per eliminare questa nota in questo momento.", "error")

    return redirect("/notes")

if __name__ == "__main__":
    context = ('Config/localhost.crt', 'Config/private_key.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)
