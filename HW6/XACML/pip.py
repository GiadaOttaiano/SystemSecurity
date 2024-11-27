from database import Note

def get_note_owner_role(note_id):
    """
    Funzione per ottenere il ruolo del proprietario della nota
    basato sull'ID della nota.
    """
    note = Note.query.get(note_id)
    if note:
        # Logica per recuperare il ruolo del proprietario (dal database o da Vault)
        # Qui supponiamo che nel database ci sia una colonna `owner_role` per ogni nota
        return note.owner_role  # Oppure un altro campo dove il ruolo è memorizzato
    return None