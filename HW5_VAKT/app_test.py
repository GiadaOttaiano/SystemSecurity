from flask import Flask, flash, render_template, request, redirect, session
import requests
import secrets
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import vakt
from vakt.rules import Eq, StartsWith, And, Greater, Less, Any

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

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

@app.route("/")
def index():
    if "vault_token" in session:
        return redirect("/dashboard")
    return render_template("login.html")

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

@app.route("/notifications")
def notifications():
    if "vault_token" not in session:
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
    if "vault_token" not in session:
        return redirect("/")

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")

    if role == "admin":
        all_notes = Note.query.all()
    else:
        all_notes = Note.query.filter_by(username=username).all()

    return render_template("notes.html", notes=all_notes, role=role, theme=theme)

@app.route("/add-note", methods=["GET", "POST"])
def add_note():
    if "vault_token" not in session:
        return redirect("/")

    role = session.get("role", "standard")
    theme = session.get("theme", "light")

    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )

        if guard.is_allowed(inquiry):
            content = request.form.get("content")
            username = session["username"]
            if content:
                new_note = Note(content=content, username=username)
                db.session.add(new_note)
                db.session.commit()

                create_notification(username, f"Hai aggiunto una nuova nota: '{content}'")
                create_notification("admin", f"Nota aggiunta da {username}: '{content}'")
                
                flash("Nota aggiunta con successo!", "success")
                return redirect("/notes")
        else:
            flash("Non hai i permessi per aggiungere una nota in questo momento.", "error")

    return render_template("add_note.html", role=role, theme=theme)

@app.route("/edit-note/<int:id>", methods=["GET", "POST"])
def edit_note(id):
    if "vault_token" not in session:
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
        inquiry = vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )

        if guard.is_allowed(inquiry):
            new_content = request.form.get("content")
            if new_content:
                old_content = note.content
                note.content = new_content
                db.session.commit()
                
                create_notification(note.username, f"Hai modificato una tua nota: '{old_content}' in '{new_content}'")
                
                flash("Nota modificata con successo!", "success")
                return redirect("/notes")
        else:
            flash("Non hai i permessi per modificare questa nota in questo momento.", "error")

    return render_template("edit_note.html", note=note, theme=theme)

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

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    context = ('Config/localhost.crt', 'Config/private_key.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)