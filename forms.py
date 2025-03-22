from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, IntegerField, DateField, HiddenField, PasswordField, ValidationError, FloatField
from wtforms.validators import DataRequired, InputRequired, NumberRange, Email, EqualTo
from models import Event, User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Jelszó', validators=[DataRequired()])
    submit = SubmitField('Bejelentkezés')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Felhasználónév', validators=[DataRequired()])
    password = PasswordField('Jelszó', validators=[DataRequired()])
    pass_confirm = PasswordField(
        'Jelszó megerősítése', validators=[DataRequired(), EqualTo('password', message='A jelszavak nem egyeznek.')])
    submit = SubmitField('Regisztrálok')


class AddTeamForm(FlaskForm):
    name = StringField('Csapatnév:', validators=[DataRequired()])
    event_id = IntegerField('event_id', validators=[
                            DataRequired()], render_kw={'readonly': True})
    submit = SubmitField('Csapat hozzáadása')


class AssignTeamForm(FlaskForm):
    team = SelectField('Válassz egy csapatot', coerce=int,
                       validators=[DataRequired()])
    group = SelectField('Válassz egy csoportot', coerce=int,
                        validators=[DataRequired()])
    submit = SubmitField('Hozzárendelés')


class MatchResultForm(FlaskForm):
    match_id = HiddenField('Match ID')
    team1_score = IntegerField('Hazai:', validators=[InputRequired(
    ), NumberRange(min=0)])
    team2_score = IntegerField('Vendég', validators=[InputRequired(
    ), NumberRange(min=0)])
    submit = SubmitField('Submit')


class AddParticipantForm(FlaskForm):
    name = StringField('Versenyzőnév:', validators=[DataRequired()])
    event_id = IntegerField('event_id', validators=[
                            DataRequired()], render_kw={'readonly': True})
    submit = SubmitField('Résztvevő hozzáadása')


class AddIndividualResultForm(FlaskForm):
    score = FloatField('Eredmény:', validators=[DataRequired(), NumberRange(
        min=0, message="A pontszám nem lehet negatív")])
    submit = SubmitField('Eredmény hozzáadása')


class AddEventForm1(FlaskForm):
    name = StringField('Event Name:', validators=[DataRequired()])
    date = DateField('Event Date:', format='%Y-%m-%d',
                     validators=[DataRequired()])
    sport_type = SelectField('Sportág:', choices=[('', '-Válassz egy sportágat-'),
                             ('football', 'Labdarúgás'),
                             ('basketball', 'Kosárlabda'),
                             ('handball', 'Kézilabda'),
                             ('volleyball', 'Röplabda'),
                             ('running', 'Futás'),
                             ('throwing', 'Dobás'),
                             ('swimming', 'Úszás')],
                             validators=[InputRequired(message="Kérlek válassz egy sportágat!")])
    submit = SubmitField('Következő')


class AddEventForm2(FlaskForm):
    event_type = SelectField('Esemény típusa:', choices=[('', '-Válassz lebonyolítást-'), ('round_robin', 'Körmérkőzéses rendszer'),
                                                         ('knockout',
                                                          'Egyenes kieséses rendszer'),
                                                         ('group_knockout', 'Csoportkörös majd egyeneskieséses rendszer')],
                             validators=[DataRequired()])
    submit = SubmitField('Következő')


class AddEventForm3(FlaskForm):
    num_of_groups = SelectField('Csoportok száma:', choices=[('', '-Válassz csoportszámot-'),
                                (2, '2 csoport'), (4, '4 csoport'), (8, '8 csoport')])
    submit = SubmitField('Esemény létrehozása')
