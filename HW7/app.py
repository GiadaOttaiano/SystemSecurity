from flask import Flask, flash, render_template, request, redirect, session
import requests
import secrets
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import logging
from form import LoginForm, ThemeForm, NoteForm, DeleteNoteForm, NotificationForm
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape  
from werkzeug.exceptions import BadRequest
import logging_manager
import XACML.vakt_manager
import json
import jsonschema
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
csrf = CSRFProtect(app)

MAX_SESSIONS = 1
SESSION_TIMEOUT = timedelta(minutes=10)

VAULT_ADDR = "https://127.0.0.1:8200"
VAULT_VERIFY = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
db = SQLAlchemy(app)

logging.basicConfig(level=logging.DEBUG)

# Memorizza la policy in VAKT
storage = XACML.vakt_manager.vakt.MemoryStorage()
storage.add(XACML.vakt_manager.policy_note)
storage.add(XACML.vakt_manager.policy_theme_non_manager_deny)
storage.add(XACML.vakt_manager.policy_theme)
storage.add(XACML.vakt_manager.policy_theme_all_users_allow)
guard = XACML.vakt_manager.vakt.Guard(storage, XACML.vakt_manager.vakt.RulesChecker())

# Modelli di database
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<Note {self.id} - {self.username}>"

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.id} - {self.username}>"
    
class ActiveSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False)
    session_id = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ActiveSession {self.user_id} - {self.session_id}>"

# Creazione delle tabelle
with app.app_context():
    db.create_all()

# Funzione di utilità per creare notifiche
def create_notification(username, message):
    notification = Notification(username=username, message=message)
    db.session.add(notification)
    db.session.commit()

# Definizione di uno schema JSON per validare i dati di risposta da Vault
vault_response_schema = {
    "type": "object",
    "properties": {
        "auth": {
            "type": "object",
            "properties": {
                "client_token": {"type": "string"},
            },
            "required": ["client_token"],
        }
    },
    "required": ["auth"]
}

@app.before_request
def check_session_timeout():
    if "last_activity" in session:
        last_activity = session["last_activity"]

        # Se last_activity è una stringa, convertila in datetime naive
        if isinstance(last_activity, str):
            last_activity = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")

        # Rendi last_activity naive, se è aware
        if last_activity.tzinfo is not None:
            last_activity = last_activity.replace(tzinfo=None)

        # Calcola la differenza temporale
        if datetime.now() - last_activity > SESSION_TIMEOUT:
            logging.info(f"Sessione scaduta per inattività. Utente: {session.get('username')}, session_id: {session.get('session_id')}.")
            flash("La tua sessione è scaduta per inattività.", "error")
            return logout()  # Termina la sessione ed effettua il logout
        
        # Aggiorna il timestamp nella sessione
        session["last_activity"] = datetime.now()

@app.route("/", methods=["GET", "POST"])
def index():
    form = LoginForm()
    if form.validate_on_submit():  # Se il form è valido
        if "access_token" in session:
            return redirect("/dashboard")
        else:
            return redirect("/")
    return render_template("login.html", form=form)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    url = f"{VAULT_ADDR}/v1/auth/ldap/login/{username}"
    payload = {"password": password}

    try:
        # Imposta header per evitare vulnerabilità legate a Content-Type
        headers = {"Content-Type": "application/json"}

        response = requests.post(url, json=payload, headers=headers, verify=VAULT_VERIFY)
        response.raise_for_status()

        # Validazione del JSON di risposta
        data = response.json()
        jsonschema.validate(instance=data, schema=vault_response_schema)

        session["vault_token"] = data["auth"]["client_token"]
        session["username"] = username
        session["last_activity"] = datetime.now()
        
        session_id = secrets.token_hex(16)

        # Verifica il numero di sessioni attive
        active_sessions = ActiveSession.query.filter_by(user_id=username).count()
        if active_sessions >= MAX_SESSIONS:
            logging.warning(f"Limite di sessioni raggiunto per l'utente {username}. Accesso negato.")
            logging_manager.log_login(username, timestamp, "sistema", None, False)
            flash("Limite di sessioni attive raggiunto. Disconnettiti da un'altra sessione.", "error")
            return redirect("/")

        # Registra la nuova sessione
        new_session = ActiveSession(user_id=username, session_id=session_id)
        db.session.add(new_session)
        db.session.commit()

        session["session_id"] = session_id
        
        logging_manager.log_login(username, timestamp, "pagina di login", session["session_id"], True)

        # Recupero del tema e del ruolo
        role = "standard"
        theme = "light"
        url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
        headers = {"X-Vault-Token": session["vault_token"]}
        response = requests.get(url, headers=headers, verify=VAULT_VERIFY)

        if response.status_code == 200:
            # Validazione del JSON segreto
            secret_data = response.json().get("data", {}).get("data", {})
            if not isinstance(secret_data, dict):
                raise ValueError("La struttura del JSON segreto non è valida.")

            theme = secret_data.get("theme", "light")
            role = secret_data.get("role", "standard")

        session["theme"] = theme
        session["role"] = role

        return redirect("/dashboard")
    except requests.exceptions.RequestException as e:
        logging.error(f"Errore durante la richiesta a Vault: {e}")
        logging_manager.log_login(username, timestamp, "pagina di login", 0, False)
        flash("Credenziali non valide. Riprova.", "error")
        return redirect("/")
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"JSON non valido ricevuto da Vault: {e}")
        logging_manager.log_login(username, timestamp, "pagina di login", 0, False)
        flash("Errore del server. Contatta l'amministratore.", "error")
        return redirect("/")
    except ValueError as e:
        logging.error(f"Errore nella struttura JSON segreta: {e}")
        logging_manager.log_login(username, timestamp, "pagina di login", 0, False)
        flash("Errore del server. Contatta l'amministratore.", "error")
        return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "vault_token" not in session:
        return redirect("/")

    theme = session.get("theme", "light")
    username = session["username"]
    role = session.get("role", "standard")

    if request.method == "POST":
        new_theme = request.form.get("theme")
        
        # Aggiungere validazione per il theme (assicurarsi che sia un valore accettabile)
        if not new_theme or not re.match("^[a-zA-Z0-9_-]+$", new_theme):
            flash("Tema non valido. Scegli un tema valido.", "error")
            return redirect("/dashboard")
        
        try:
            # Ottieni i dati da Vault
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
            headers = {"X-Vault-Token": session["vault_token"]}
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()

            # Validazione del JSON di risposta
            data = response.json()
            jsonschema.validate(instance=data, schema=vault_response_schema)  

            # Dump dei dati JSON ricevuti (per log e debug)
            secret_data = data.get("data", {}).get("data", {})
            json_data = json.dumps(secret_data, indent=4)  # Serializzazione del JSON
            logging.info(f"JSON ricevuto da Vault: {json_data}")  # Log del JSON

            # Verifica che i dati siano nel formato corretto prima di aggiornarli
            if not isinstance(secret_data, dict):
                raise ValueError("La struttura del JSON segreto non è valida.")

            secret_data["theme"] = new_theme

            # Verifica che l'utente abbia il permesso di aggiornare il tema
            if role == "admin" or role == "standard":
                payload = {"data": secret_data}

                # Validazione JSON per il payload
                try:
                    json.dumps(payload)  # Verifica che il payload sia serializzabile in JSON
                except (TypeError, ValueError) as e:
                    raise BadRequest(f"Errore di serializzazione JSON: {e}")

                response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)
                response.raise_for_status()

                session["theme"] = new_theme
            else:
                flash("Non hai i permessi per modificare il tema.", "error")

        except requests.exceptions.RequestException as e:
            flash(f"Failed to update theme: {e}", "error")
            return redirect("/dashboard")
        except BadRequest as e:
            flash(f"Errore nella richiesta: {e}", "error")
            return redirect("/dashboard")
        except jsonschema.exceptions.ValidationError as e:
            logging.error(f"JSON non valido ricevuto da Vault: {e}")
            flash("Errore del server. Contatta l'amministratore.", "error")
            return redirect("/dashboard")
        except ValueError as e:
            logging.error(f"Errore nella struttura JSON segreta: {e}")
            flash("Errore del server. Contatta l'amministratore.", "error")
            return redirect("/dashboard")

    # Rendi visibile il tema e il ruolo nella dashboard
    return render_template("dashboard.html", username=username, theme=theme, role=role)


@app.route("/account-settings", methods=["GET", "POST"])
def account_settings():
    if "vault_token" not in session:  # Verifica se l'utente è autenticato
        return redirect("/")  # Se no, reindirizza al login

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    current_time = datetime.now().strftime("%H:%M:%S")  # Ottieni l'orario corrente

    # Verifica solo se si tenta di modificare il tema
    if request.method == "POST" and 'theme' in request.form:
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='theme',
            subject={'role': session['role']}, 
            context={'current_time': current_time}
        )

        if not guard.is_allowed(inquiry):  # Se la policy non consente, blocca l'accesso
            logging_manager.theme(username, timestamp, "account settings", session["session_id"], False)
            flash("Non hai i permessi per modificare il tema in questo momento.", "error")
            return redirect("/dashboard")  # Reindirizza alla dashboard se la modifica non è consentita

    form = ThemeForm()

    if request.method == "POST" and form.validate_on_submit():
        new_theme = form.theme.data
        try:
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
            headers = {"X-Vault-Token": session["vault_token"]}
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()

            secret_data = response.json().get("data", {}).get("data", {})
            secret_data["theme"] = new_theme
            payload = {"data": secret_data}

            response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)
            response.raise_for_status()

            session["theme"] = new_theme  # Aggiorna il tema nella sessione
            session["last_activity"] = datetime.now()
            
            logging_manager.theme(username, timestamp, "account settings", session["session_id"], True)
            flash("Tema modificato con successo!", "success")
        except requests.exceptions.RequestException as e:
            logging_manager.theme(username, timestamp, "sistema", session["session_id"], False)
            flash(f"Errore nell'aggiornamento del tema: {e}", "error")

    return render_template("account_settings.html", username=username, role=role, theme=theme, form=form)

@app.route("/notifications", methods=["GET", "POST"])
def notifications():
    if "vault_token" not in session:
        return redirect("/")

    username = session["username"]
    theme = session.get("theme", "light")
    
    # Ottieni le notifiche dell'utente
    user_notifications = Notification.query.filter_by(username=username).order_by(Notification.timestamp.desc()).all()
    
    # Crea un oggetto form per la cancellazione di tutte le notifiche
    form = NotificationForm()
    
    # Se il form "clear all" è inviato, elimina tutte le notifiche
    if form.submit_clear_all.data and form.validate_on_submit():
        Notification.query.filter_by(username=username).delete()
        db.session.commit()
        session["last_activity"] = datetime.now()
        flash("Tutte le notifiche sono state eliminate.", "success")
        return redirect("/notifications")

    # Per ogni notifica, crea un form per eliminarla singolarmente
    form_delete = {}
    for notification in user_notifications:
        form_delete[notification.id] = NotificationForm()
        session["last_activity"] = datetime.now()

    return render_template("notifications.html", 
                           notifications=user_notifications, 
                           theme=theme,
                           form=form,
                           form_delete=form_delete)

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
    if "vault_token" not in session:
        return redirect("/")

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    form = DeleteNoteForm()

    if role == "admin" or role == "manager":
        all_notes = Note.query.all()
        session["last_activity"] = datetime.now()
    else:
        all_notes = Note.query.filter_by(username=username).all()
        session["last_activity"] = datetime.now()

    return render_template("notes.html", notes=all_notes, role=role, theme=theme, form=form)

@app.route("/add-note", methods=["GET", "POST"])
def add_note():
    if "vault_token" not in session:
        return redirect("/")

    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    form = NoteForm()  # Usa il NoteForm per gestire il modulo
    
    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )
        session["last_activity"] = datetime.now()

        if guard.is_allowed(inquiry):
            
            if form.validate_on_submit():  # Verifica che il modulo sia valido
                content = form.content.data  # Ottieni il contenuto dal form
                # Escape il contenuto per evitare XSS
                safe_content = escape(content)
                username = session["username"]
                
                new_note = Note(content=safe_content, username=username)
                db.session.add(new_note)
                db.session.commit()
                
                # Log dell'azione
                logging_manager.log_audit(username, 'creazione', 'note', timestamp, session['session_id'], 'successo')

                create_notification(username, f"Hai aggiunto una nuova nota: '{safe_content}'")
                create_notification("admin", f"Nota aggiunta da {username}: '{safe_content}'")
                
                flash("Nota aggiunta con successo!", "success")
                return redirect("/notes")                
        else:
            logging.warning(f"Accesso negato: policy restrictiva. Utente: {session['username']}, Azione: {inquiry.action}, Risorsa: {inquiry.resource}.")
            logging_manager.log_audit(session["username"], 'creazione', 'note', timestamp, session['session_id'], 'fallimento')
            flash("Non hai i permessi per aggiungere una nota in questo momento.", "error")

    return render_template("add_note.html", form=form, role=role, theme=theme)

@app.route("/edit-note/<int:id>", methods=["GET", "POST"])
def edit_note(id):
    if "vault_token" not in session:
        return redirect("/")

    note = Note.query.get_or_404(id)  # Recupera la nota dal DB
    form = NoteForm(obj=note)  # Usa il form per pre-popolare il campo con il contenuto attuale
    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Verifica se l'utente ha il permesso di modificare la nota
    if note.username != username and role != "admin":
        flash("Non hai i permessi per modificare questa nota.", "error")
        return redirect("/notes")

    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )
        session["last_activity"] = datetime.now()

        if guard.is_allowed(inquiry):  # Verifica se l'utente ha il permesso tramite guard
            if form.validate_on_submit():  # Se il form è valido
                old_content = note.content  # Memorizza il contenuto precedente
                note.content = form.content.data  # Aggiorna il contenuto con quello del form
                db.session.commit()  # Salva i cambiamenti nel DB
                
                # Log dell'azione
                logging_manager.log_audit(username, 'modifica', 'note', timestamp, session['session_id'], 'successo')

                # Notifica dell'aggiornamento
                create_notification(note.username, f"Hai modificato una tua nota: '{old_content}' in '{note.content}'")

                flash("Nota modificata con successo!", "success")
                return redirect("/notes")
        else:
            logging.warning(f"Accesso negato: policy restrittiva. Utente: {session['username']}, Azione: {inquiry.action}, Risorsa: {inquiry.resource}.")
            logging_manager.log_audit(session["username"], 'modifica', 'note', timestamp, session['session_id'],'fallimento')
            flash("Non hai i permessi per modificare questa nota in questo momento.", "error")

    return render_template("edit_note.html", form=form, note=note, theme=theme)

@app.route("/delete-note/<int:id>", methods=["POST"])
def delete_note(id):
    if "vault_token" not in session:
        return redirect("/")

    note = Note.query.get_or_404(id)
    username = session["username"]
    role = session.get("role", "standard")
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    if note.username != username and role != "admin":
        flash("Non hai i permessi per eliminare questa nota.", "error")
        return redirect("/notes")

    # Crea il form di delete
    form = DeleteNoteForm()

    if form.validate_on_submit():  # Gestisce il CSRF automaticamente
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )
        session["last_activity"] = datetime.now()

        if guard.is_allowed(inquiry):
            content = note.content
            db.session.delete(note)
            db.session.commit()
            
            # Log dell'azione
            logging_manager.log_audit(username, 'eliminazione', 'note', current_time, session['session_id'], 'successo')

            create_notification(note.username, f"Hai eliminato una tua nota: '{content}'")
            create_notification("admin", f"Nota eliminata da {username}: '{content}'")

            flash("Nota eliminata con successo!", "success")
            return redirect("/notes")
        else:
            logging.warning(f"Accesso negato: policy restrittiva. Utente: {session['username']}, Azione: {inquiry.action}, Risorsa: {inquiry.resource}.")
            flash("Non hai i permessi per eliminare questa nota in questo momento.", "error")
            return redirect("/notes")
    else:
        logging_manager.log_audit(session["username"], 'eliminazione', 'note', timestamp, session['session_id'], 'fallimento')
        flash("Errore nel tentativo di eliminare la nota.", "error")
        return redirect("/notes")

@app.route("/logout")
def logout():
    session_id = session.get("session_id")
    if session_id:
        ActiveSession.query.filter_by(session_id=session_id).delete()
        db.session.commit()
        
    current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    logging_manager.logout(session["username"], current_time, "sistema", session["session_id"])

    session.clear()
    return redirect("/")

if __name__ == "__main__":
    context = ('Config/localhost.crt', 'Config/private_key.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)