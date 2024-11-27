from datetime import datetime

def evaluate_request(action, resource, policy, current_time=None):
    """
    Valuta la richiesta rispetto alla policy.
    
    Args:
        action (str): Azione richiesta (es. "modify").
        resource (str): Risorsa richiesta (es. "note").
        policy (dict): Policy parsata.
        current_time (str): Orario corrente (HH:MM:SS).
    
    Returns:
        str: "Permit" o "Deny".
    """
    if not policy:
        return "Deny"  # Se la policy non è caricata, nega tutto
    
    # Controlla il target
    if action != "modify" or resource != "note":
        return "Deny"

    # Usa l'orario corrente se non specificato
    if not current_time:
        current_time = datetime.now().strftime("%H:%M:%S")
    
    # Verifica la fascia oraria consentita
    allow_start = policy["allow"]["start"]
    allow_end = policy["allow"]["end"]
    
    if allow_start <= current_time <= allow_end:
        return "Permit"
    else:
        return "Deny"
