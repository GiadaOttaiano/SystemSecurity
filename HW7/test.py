from flask import Flask, flash, render_template, request, redirect, session
import requests
import secrets
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import vakt
from vakt.rules import Eq, StartsWith, And, Greater, Less, Any
from form import LoginForm, ThemeForm, NoteForm, DeleteNoteForm, NotificationForm
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape  

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
csrf = CSRFProtect(app)

VAULT_ADDR = "https://127.0.0.1:8200"
VAULT_VERIFY = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
db = SQLAlchemy(app)

# Definisci la policy in VAKT
policy = vakt.Policy(
    123456,
    actions=[Eq('modify')],
    resources=[StartsWith('note')],
    subjects=[{'username': Any()}],  # L'utente può essere qualsiasi
    effect=vakt.ALLOW_ACCESS,
    context={'current_time': And(Greater('09:00:00'), Less('18:00:00'))},
    description="""Consenti la modifica delle note solo tra le 9:00 e le 18:00"""
)

# Memorizza la policy in VAKT
storage = vakt.MemoryStorage()
storage.add(policy)
guard = vakt.Guard(storage, vakt.RulesChecker())

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

# Creazione delle tabelle
with app.app_context():
    db.create_all()

# Funzione di utilità per creare notifiche
def create_notification(username, message):
    notification = Notification(username=username, message=message)
    db.session.add(notification)
    db.session.commit()
    
# Funzione di sicurezza
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response

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

    url = f"{VAULT_ADDR}/v1/auth/ldap/login/{username}"
    payload = {"password": password}
    try:
        response = requests.post(url, json=payload, verify=VAULT_VERIFY)
        response.raise_for_status()

        data = response.json()
        session["vault_token"] = data["auth"]["client_token"]
        session["username"] = username

        role = "standard"
        theme = "light"
        url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
        headers = {"X-Vault-Token": session["vault_token"]}
        response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
        if response.status_code == 200:
            secret_data = response.json().get("data", {}).get("data", {})
            theme = secret_data.get("theme", "light")
            role = secret_data.get("role", "standard")
        session["theme"] = theme
        session["role"] = role

        return redirect("/dashboard")
    except requests.exceptions.RequestException:
        flash("Credenziali non valide. Riprova.", "error")
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
        try:
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
            headers = {"X-Vault-Token": session["vault_token"]}
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()

            secret_data = response.json().get("data", {}).get("data", {})
            secret_data["theme"] = new_theme

            # Verifica che l'utente abbia il permesso di aggiornare il tema
            if role == "admin" or role == "standard":
                payload = {"data": secret_data}
                response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)
                response.raise_for_status()

                session["theme"] = new_theme
            else:
                flash("Non hai i permessi per modificare il tema.", "error")

        except requests.exceptions.RequestException as e:
            return f"Failed to update theme: {e}", 500

    return render_template("dashboard.html", username=username, theme=theme, role=role)

@app.route("/account-settings", methods=["GET", "POST"])
def account_settings():
    if "vault_token" not in session:  # Verifica se l'utente è autenticato
        return redirect("/")  # Se no, reindirizza al login

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")

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
            flash("Tema modificato con successo!", "success")
        except requests.exceptions.RequestException as e:
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
        flash("Tutte le notifiche sono state eliminate.", "success")
        return redirect("/notifications")

    # Per ogni notifica, crea un form per eliminarla singolarmente
    form_delete = {}
    for notification in user_notifications:
        form_delete[notification.id] = NotificationForm()

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

    if role == "admin":
        all_notes = Note.query.all()
    else:
        all_notes = Note.query.filter_by(username=username).all()

    return render_template("notes.html", notes=all_notes, role=role, theme=theme, form=form)

from markupsafe import escape  # Importa il modulo per fare escape dei dati

@app.route("/add-note", methods=["GET", "POST"])
def add_note():
    if "vault_token" not in session:
        return redirect("/")

    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    form = NoteForm()  # Usa il NoteForm per gestire il modulo
    
    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )

        if guard.is_allowed(inquiry):
            
            if form.validate_on_submit():  # Verifica che il modulo sia valido
                content = form.content.data  # Ottieni il contenuto dal form
                # Escape il contenuto per evitare XSS
                safe_content = escape(content)
                username = session["username"]
                new_note = Note(content=safe_content, username=username)
                db.session.add(new_note)
                db.session.commit()

                create_notification(username, f"Hai aggiunto una nuova nota: '{safe_content}'")
                create_notification("admin", f"Nota aggiunta da {username}: '{safe_content}'")
                
                flash("Nota aggiunta con successo!", "success")
                return redirect("/notes")
        else:
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

    # Verifica se l'utente ha il permesso di modificare la nota
    if note.username != username and role != "admin":
        flash("Non hai i permessi per modificare questa nota.", "error")
        return redirect("/notes")

    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )

        if guard.is_allowed(inquiry):  # Verifica se l'utente ha il permesso tramite guard
            if form.validate_on_submit():  # Se il form è valido
                old_content = note.content  # Memorizza il contenuto precedente
                note.content = form.content.data  # Aggiorna il contenuto con quello del form
                db.session.commit()  # Salva i cambiamenti nel DB

                # Notifica dell'aggiornamento
                create_notification(note.username, f"Hai modificato una tua nota: '{old_content}' in '{note.content}'")

                flash("Nota modificata con successo!", "success")
                return redirect("/notes")
        else:
            flash("Non hai i permessi per modificare questa nota in questo momento.", "error")

    return render_template("edit_note.html", form=form, note=note, theme=theme)

@app.route("/delete-note/<int:id>", methods=["POST"])
def delete_note(id):
    if "vault_token" not in session:
        return redirect("/")

    note = Note.query.get_or_404(id)
    username = session["username"]
    role = session.get("role", "standard")

    if note.username != username and role != "admin":
        flash("Non hai i permessi per eliminare questa nota.", "error")
        return redirect("/notes")

    # Crea il form di delete
    form = DeleteNoteForm()

    if form.validate_on_submit():  # Gestisce il CSRF automaticamente
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )

        if guard.is_allowed(inquiry):
            content = note.content
            db.session.delete(note)
            db.session.commit()

            create_notification(note.username, f"Hai eliminato una tua nota: '{content}'")
            create_notification("admin", f"Nota eliminata da {username}: '{content}'")

            flash("Nota eliminata con successo!", "success")
            return redirect("/notes")
        else:
            flash("Non hai i permessi per eliminare questa nota in questo momento.", "error")
            return redirect("/notes")
    else:
        flash("Errore nel tentativo di eliminare la nota.", "error")
        return redirect("/notes")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    context = ('Config/localhost.crt', 'Config/private_key.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)