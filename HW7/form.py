from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import InputRequired

# Definisci il form di login con Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    
# Form per il cambio del tema
class ThemeForm(FlaskForm):
    theme = SelectField('Choose Theme', choices=[('light', 'Light'), ('dark', 'Dark')])
    
class NoteForm(FlaskForm):
    content = StringField('Contenuto', validators=[InputRequired()])
    
class DeleteNoteForm(FlaskForm):
    submit = SubmitField("Elimina")  
    
class NotificationForm(FlaskForm):
    submit_clear_all = SubmitField('Elimina tutte le notifiche')
    submit_delete = SubmitField('Elimina')