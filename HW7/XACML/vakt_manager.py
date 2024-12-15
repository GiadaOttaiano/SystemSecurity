import vakt
from vakt.rules import Eq, StartsWith, And, Greater, Less, Or, Not, Any

# Definisci la policy in VAKT
policy_note = vakt.Policy(
    123456,
    actions=[Eq('modify')],
    resources=[StartsWith('note')],
    subjects=[{'username': Any()}],  # L'utente può essere qualsiasi
    effect=vakt.ALLOW_ACCESS,
    context={'current_time': And(Greater('09:00:00'), Less('18:00:00'))},
    description="""Consenti la modifica delle note solo tra le 9:00 e le 18:00"""
)

policy_theme_all_users_allow = vakt.Policy(
    123457,
    actions=[Eq('modify')],
    resources=[StartsWith('theme')],
    subjects=[{'role': Any() }],  # Per tutti gli utenti (qualsiasi ruolo)
    effect=vakt.ALLOW_ACCESS,
    context={'current_time': And(Greater('08:00:00'), Less('16:00:00'))},  # Tra le 08:00 e le 16:00
    description="""Permette a tutti gli utenti di modificare il tema tra le 08:00 e le 16:00"""
)

policy_theme_non_manager_deny = vakt.Policy(
    123458,
    actions=[Eq('modify')],
    resources=[StartsWith('theme')],
    subjects=[{'role': Not(Eq('manager'))}],  # Utenti non manager
    effect=vakt.DENY_ACCESS,
    context={'current_time': And(Less('08:00:00'), Greater('16:00:00'))}, 
    description="""Negare la modifica del tema agli utenti non manager tra le 16:00 e le 7:59"""
)

policy_theme = vakt.Policy(
    123459,
    actions=[Eq('modify')],
    resources=[StartsWith('theme')],
    subjects=[{'role': Eq('manager')}],  # Solo utenti con ruolo manager
    effect=vakt.ALLOW_ACCESS,
    context={'current_time': And(Greater('08:00:00'), Less('17:00:00'))},  
    description="""Permette ai manager di modificare il tema solo tra le 8:00 e le 17:00"""
)
