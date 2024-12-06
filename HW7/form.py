from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import InputRequired

# Form per il login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    
# Form per il cambio del tema
class ThemeForm(FlaskForm):
    theme = SelectField('Choose Theme', choices=[('light', 'Light'), ('dark', 'Dark')])
    
# Form per la creazione di una nuova nota
class NoteForm(FlaskForm):
    content = StringField('Contenuto', validators=[InputRequired()])
    
# Form per la cancellazione di una nota
class DeleteNoteForm(FlaskForm):
    submit = SubmitField("Elimina")  
    
# Form per le notifiche
class NotificationForm(FlaskForm):
    submit_clear_all = SubmitField('Elimina tutte le notifiche')
    submit_delete = SubmitField('Elimina')