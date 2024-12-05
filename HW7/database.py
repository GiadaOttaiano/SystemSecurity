from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Inizializza l'oggetto db, che sarà usato nel resto dell'applicazione
db = SQLAlchemy()

# Struttura della tabella delle note
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