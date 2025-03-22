from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()


def init_db(app):
    db.init_app(app)
    Migrate(app, db)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, email, username, password):
        self.email = email
        self.username = username
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    sport_type = db.Column(db.String(50), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    num_of_groups = db.Column(db.Integer)
    is_ended = db.Column(db.Boolean, default=False)

    # Idegen kulcs nevének megadása
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id', name='fk_user_event'), nullable=False)

    user = db.relationship('User', backref='events')
    teams = db.relationship('Team', backref='event',
                            cascade="all, delete-orphan")
    groups = db.relationship('Group', backref='event',
                             cascade="all, delete-orphan")
    matches = db.relationship('Match', backref='event',
                              cascade="all, delete-orphan")
    participants = db.relationship(
        'Participant', backref='event', cascade="all, delete-orphan")
    individual_results = db.relationship(
        'Individual_Result', backref='event', cascade="all, delete-orphan")

    def __init__(self, name, date, sport_type, event_type, num_of_groups, is_ended, user_id):
        self.name = name
        self.date = date
        self.sport_type = sport_type
        self.event_type = event_type
        self.num_of_groups = num_of_groups
        self.is_ended = is_ended
        self.user_id = user_id

    def __repr__(self):
        return f"Esemény: {self.name}, {self.date} sport: {self.sport_type} ({self.event_type}) csoportok száma: {self.num_of_groups}, tulajdonos: {self.user_id}"


class Team(db.Model):
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey(
        'events.id', name='fk_team_event'), nullable=False)
    group_id = db.Column(db.Integer)

    def __init__(self, name, event_id, group_id):
        self.name = name
        self.event_id = event_id
        self.group_id = group_id

    def __repr__(self):
        return f"Team: {self.name}, Event ID: {self.event_id} group id {self.group_id}"


class Group(db.Model):

    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey(
        'events.id', name='fk_team_event'), nullable=False)

    def __init__(self, name, event_id):
        self.name = name
        self.event_id = event_id

    def __repr__(self):
        return f"Csoport jele: {self.name} esemény id: {self.event_id}"


class Match(db.Model):
    __tablename__ = "matches"
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey(
        'events.id', name='fk_team_event'), nullable=False)

    team1_score = db.Column(db.Integer)
    team2_score = db.Column(db.Integer)
    team1_id = db.Column(db.Integer, db.ForeignKey(
        'teams.id', name='fk_match_team1'), nullable=False)
    team2_id = db.Column(db.Integer, db.ForeignKey(
        'teams.id', name='fk_match_team2'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey(
        'groups.id', name='fk_match_group'))

    team1 = db.relationship('Team', foreign_keys=[team1_id])
    team2 = db.relationship('Team', foreign_keys=[team2_id])

    def __init__(self, event_id, team1_score, team2_score, team1_id, team2_id, group_id):
        self.event_id = event_id
        self.team1_score = team1_score
        self.team2_score = team2_score
        self.team1_id = team1_id
        self.team2_id = team2_id
        self.group_id = group_id

    def __repr__(self):
        return (f"A {self.id}. számú mérkőzés eredménye: "
                f"{self.team1_id} ({self.team1_score}) - "
                f"{self.team2_id} ({self.team2_score})")


class Participant(db.Model):
    __tablename__ = "participants"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey(
        'events.id'), nullable=False)
    individual_results = db.relationship(
        'Individual_Result', backref='participant', lazy=True)

    def __init__(self, event_id, name):
        self.event_id = event_id
        self.name = name

    def __repr__(self):
        return (f"A versenyző ID: {self.id} a versenyző neve: {self.name} esemény ID: {self.event_id}")


class Individual_Result(db.Model):
    __tablename__ = "individual_result"
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey(
        'events.id'), nullable=False)
    participant_id = db.Column(db.Integer, db.ForeignKey(
        'participants.id'), nullable=False)
    score = db.Column(db.Float)

    def __init__(self, event_id, participant_id, score):
        self.event_id = event_id
        self.participant_id = participant_id
        self.score = score

    def __repr__(self):
        return (f"Esemény ID: {self.event_id} versenyző ID: {self.participant_id}, a versenyző eredmény: {self.score}")
