import logging

# Configurazione di base del logger
logging.basicConfig(
    filename='audit_logs.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
)

def log_audit(username, action, resource, timestamp, session_id, status):
    """
    Registra un'azione eseguita da un utente nel log degli audit.

    :param username: Username dell'utente che ha eseguito l'azione.
    :param action: Tipo di azione eseguita (es. 'creazione', 'modifica', 'eliminazione').
    :param resource: Nome della risorsa (es. 'note').
    :param timestamp: Timestamp dell'operazione.
    :param session_id: ID della sessione dell'utente.
    :param status: Stato dell'operazione (es. 'successo', 'fallimento').
    :param error: Errore operazione.
    """
    
    log_message = f"User: {username} | Action: {action} | Resource: {resource} | Timestamp: {timestamp} | Session ID: {session_id} | Status: {status} "
    logging.info(log_message)
    
def log_login(username, timestamp, resource, session_id, success):
    status = 'successo' if success else 'fallimento'
    
    log_audit(username, 'accesso', resource, timestamp, session_id, status)

def logout(username, timestamp, resource, session_id):
    log_audit(username, 'logout', resource, timestamp, session_id, 'successo')