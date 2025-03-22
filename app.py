from flask import render_template, make_response
from flask_login import login_user
from flask import request, redirect, url_for, flash, render_template
import os
from flask import Flask, render_template, url_for, redirect, request, flash, session, abort
from forms import AddTeamForm, AssignTeamForm, MatchResultForm, AddParticipantForm, AddIndividualResultForm, AddEventForm1, AddEventForm2, AddEventForm3, LoginForm, RegistrationForm
from models import db, Event, init_db, Team, Group, Match, Participant, Individual_Result, User
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
from flask_login import login_user, login_required, logout_user, current_user
import csv
import io


login_manager = LoginManager()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
init_db(app)

login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Kérjük, jelentkezz be az oldal eléréséhez."
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/welcome')
@login_required
def welcome_user():
    return render_template('welcome_user.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sikeresen kilépett.', 'success')  # Flash üzenet beállítása
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get('next')
            if not next or not next.startswith('/'):
                next = url_for('list_events')
            return redirect(next)
        else:
            flash('Hibás email vagy jelszó. Próbálja újra.',)

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        existing_user_username = User.query.filter_by(
            username=form.username.data).first()
        existing_user_email = User.query.filter_by(
            email=form.email.data).first()

        if existing_user_username:
            flash('Ez a felhasználónév már foglalt. Kérjük, válasszon másikat.', 'error')
            return redirect(url_for('register'))

        if existing_user_email:
            flash(
                'Ez az email cím már foglalt. Kérjük, használjon másik email címet.', 'error')
            return redirect(url_for('register'))

        # Ha minden rendben, létrehozzuk a felhasználót
        user = User(email=form.email.data,
                    username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        flash('Köszönjük a regisztrációd! \n Lépj be a folytatáshoz!', 'success')
        return redirect(url_for('login'))

    # Ha nem sikeres a validáció, kezeljük a hibákat
    if form.errors:
        # Iterálunk a form hibákon és flash üzenetben jelenítjük meg
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{error}', 'error')

    return render_template('register.html', form=form)


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/list')
@login_required
def list_events():
    events = Event.query.filter_by(user_id=current_user.id).all()
    return render_template('list.html', events=events)


@app.route('/delete', methods=['POST'])
@login_required
def del_event():
    event_id = request.form.get('event_id')
    event = Event.query.get(event_id)
    if event and event.user_id == current_user.id:
        db.session.delete(event)
        db.session.commit()
    events = Event.query.filter_by(user_id=current_user.id).all()
    return render_template('list.html', events=events)


@app.route('/manage_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def manage_event(event_id):
    event = Event.query.get_or_404(event_id)
    teams = Team.query.filter_by(event_id=event_id).all()
    groups = Group.query.filter_by(event_id=event_id).all()
    matches = Match.query.filter_by(event_id=event_id).all()
    max_group_id = db.session.query(func.max(Match.group_id)).filter_by(
        event_id=event_id).scalar()
    participants = Participant.query.filter_by(
        event_id=event_id).all()  # Lekérjük az egyéni résztvevőket
    event_state = set_type_of_match(
        event_id, max_group_id)

    if event.user_id != current_user.id:
        abort(403)

    if event.event_type == "group_knockout":
        return render_template('manage_event_for_group_knockout.html', event=event, teams=teams, groups=groups, matches=matches, event_state=event_state, max_group_id=max_group_id)
    elif event.event_type == "knockout":
        return render_template('manage_event_for_knockout.html', event=event, teams=teams, groups=groups, matches=matches, event_state=event_state, max_group_id=max_group_id)
    elif event.event_type == "round_robin":
        return render_template('manage_event_for_round_robin.html', event=event, teams=teams, groups=groups, matches=matches, event_state=event_state, max_group_id=max_group_id)
    elif event.event_type == "individual_sport":
        return render_template('manage_event_for_individual.html', event=event, participants=participants, matches=matches, event_state=event_state)


@app.route('/add_team/<int:event_id>', methods=['GET', 'POST'])
@login_required
def add_team(event_id):
    form = AddTeamForm()

    event = Event.query.get(event_id)
    if event.user_id != current_user.id:
        abort(403)
    form.event_id.data = event_id

    teams = Team.query.filter_by(event_id=event_id).all()
    existing_groups = Group.query.filter_by(event_id=event_id).all()

    if form.validate_on_submit():
        name = form.name.data

        new_team = Team(name=name, event_id=event_id, group_id=None)
        db.session.add(new_team)
        db.session.commit()

        return redirect(url_for('add_team', event_id=event_id))

    return render_template('add_team.html', form=form, event=event, teams=teams, existing_groups=existing_groups)


@app.route('/delete_team', methods=['POST'])
@login_required
def del_team():
    team_id = request.form.get('team_id')
    event_id = request.form.get('event_id')

    if team_id:
        team = Team.query.get(team_id)
        if team:
            db.session.delete(team)
            db.session.commit()

    return redirect(url_for('add_team', event_id=event_id))


# # CREATE RR MATCHES
@app.route('/create_round_robin_matches/<int:event_id>', methods=['GET', 'POST'])
@login_required
def create_round_robin_matches(event_id):
    group_id = Group.query.filter_by(event_id=event_id).first().id
    teams = Team.query.filter_by(event_id=event_id).all()
    existing_matches = Match.query.filter_by(event_id=event_id).all()
    if existing_matches:
        return redirect(url_for('list_of_round_robin_matches', event_id=event_id))
    for i in range(len(teams)):
        for j in range(i + 1, len(teams)):
            match = Match(
                event_id=event_id,
                group_id=group_id,
                team1_id=teams[i].id,
                team2_id=teams[j].id,
                team1_score=None,
                team2_score=None
            )
            db.session.add(match)
    db.session.commit()
    return redirect(url_for('list_of_round_robin_matches', event_id=event_id))


@app.route('/list_of_round_robin_matches/<int:event_id>', methods=['GET', 'POST'])
@login_required
def list_of_round_robin_matches(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    group = Group.query.filter_by(event_id=event_id).first()
    group_id = group.id
    matches = Match.query.filter_by(event_id=event_id)
    round_robin_checker = is_group_complete_by_group_id(event_id, group_id)
    not_draw_in_group = is_not_draw_in_group(event_id, group_id)
    return render_template('list_of_round_robin_matches.html', event=event, matches=matches, round_robin_checker=round_robin_checker, not_draw_in_group=not_draw_in_group)


@app.route('/close_round_robin_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def close_round_robin_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    group = Group.query.filter_by(event_id=event_id).first()
    group_id = group.id
    round_robin_checker = is_group_complete_by_group_id(event_id, group_id)
    if round_robin_checker:
        event.is_ended = True
        db.session.commit()
    return redirect(url_for('list_of_round_robin_matches', event_id=event_id))


@app.route('/round_robin_overview/<int:event_id>', methods=['GET', 'POST'])
@login_required
def round_robin_overview(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    group = Group.query.filter_by(event_id=event_id).first()
    group_id = group.id
    group_ids = []
    group_ids.append(group_id)
    group_data = generate_group_data_overview(event_id, group_ids)
    group_data = dict(list(group_data.items()))
    return render_template('round_robin_overview.html', event=event, group_data=group_data)


@app.route('/create_groups/<int:event_id>')
@login_required
def create_groups(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    existing_groups = Group.query.filter_by(event_id=event_id).all()
    team_count = db.session.query(func.count(
        Team.id)).filter_by(event_id=event_id).scalar()

    if existing_groups and event.event_type == "group_knockout":
        return redirect(url_for('assign_team_to_group', event_id=event_id))

    if event.event_type == "group_knockout":
        if event.num_of_groups == 2:
            group_names = ['A', 'B', 'S', 'Final']
        elif event.num_of_groups == 4:
            group_names = ['A', 'B', 'C', 'D', 'Q', 'S', 'Final']
        elif event.num_of_groups == 8:
            group_names = ['A', 'B', 'C', 'D', 'E',
                           'F', 'G', 'H', 'R16', 'Q', 'S', 'Final']
        for name in group_names:
            group = Group(name=name, event_id=event_id)
            db.session.add(group)
        db.session.commit()
        return redirect(url_for('assign_team_to_group', event_id=event_id))

    if existing_groups and event.event_type == "knockout":
        return redirect(url_for('create_first_knockout', event_id=event_id))

    if event.event_type == "knockout":
        if team_count == 2:
            group_names = ['Final']
        if team_count == 4:
            group_names = ['S', 'Final']
        if team_count == 8:
            group_names = ['Q', 'S', 'Final']
        if team_count == 16:
            group_names = ['R16', 'Q', 'S', 'Final']
        if team_count == 32:
            group_names = ['R32', 'R16', 'Q', 'S', 'Final']
        for name in group_names:
            group = Group(name=name, event_id=event_id)
            db.session.add(group)
        db.session.commit()
        return redirect(url_for('create_first_knockout', event_id=event_id))

    if existing_groups and event.event_type == "round_robin":
        return redirect(url_for('create_round_robin_matches', event_id=event_id))

    if event.event_type == "round_robin":
        group = Group(name=f'RR', event_id=event_id)
        db.session.add(group)
        db.session.commit()
        group_id = Group.query.filter_by(event_id=event_id).first().id
        teams = Team.query.filter_by(event_id=event_id).all()
        for team in teams:
            team.group_id = group_id
            db.session.commit()

        return redirect(url_for('create_round_robin_matches', event_id=event_id))

# ELSŐ KIESÉSES SZAKASZ


@app.route('/create_first_knockout/<int:event_id>')
@login_required
def create_first_knockout(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    teams = Team.query.filter_by(event_id=event_id)
    group = Group.query.filter_by(event_id=event_id).first()
    knockout_first_group_id = group.id
    # Ellenőrizzük, hogy a kieséses mérkőzések már léteznek-e
    existing_knockout_matches = Match.query.filter_by(
        event_id=event_id, group_id=knockout_first_group_id).all()

    if not existing_knockout_matches:
        knockout_matches = []

        for team in teams:
            knockout_matches.append(team)

        for i in range(0, len(knockout_matches), 2):
            new_match = Match(
                event_id=event_id,
                group_id=knockout_first_group_id,
                team1_id=knockout_matches[i].id,
                team2_id=knockout_matches[i+1].id,
                team1_score=None,
                team2_score=None
            )
            db.session.add(new_match)

        db.session.commit()

    return redirect(url_for('list_knockout_stage_matches', event_id=event_id, group_id=knockout_first_group_id))


@app.route('/assign_team_to_group/<int:event_id>', methods=['GET', 'POST'])
@login_required
def assign_team_to_group(event_id):
    form = AssignTeamForm()
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    teams = Team.query.filter_by(event_id=event_id).all()
    groups = Group.query.filter_by(event_id=event_id).all()
    existing_matches = Match.query.filter_by(event_id=event_id).all()
    form.team.choices = [(team.id, team.name) for team in teams]
    form.group.choices = [(group.id, group.name)
                          for group in groups[:event.num_of_groups]]
    all_assigned = True
    for team in teams:
        if team.group_id is None:
            all_assigned = False
            break
    if form.validate_on_submit():
        team_id = form.team.data
        group_id = form.group.data

        team = Team.query.get(team_id)
        team.group_id = group_id
        db.session.commit()

        return redirect(url_for('assign_team_to_group', event_id=event_id))
    return render_template('assign_team_to_group.html', event=event, teams=teams, groups=groups, form=form, all_assigned=all_assigned, existing_matches=existing_matches)


@app.route('/create_group_matches/<int:event_id>', methods=['GET', 'POST'])
@login_required
def create_group_matches(event_id):
    groups = Group.query.filter_by(event_id=event_id).all()
    teams = Team.query.filter_by(event_id=event_id).all()
    group_ids = [group.id for group in groups]
    existing_matches = Match.query.filter_by(event_id=event_id).all()
    if existing_matches:
        return redirect(url_for('select_match', event_id=event_id))

    for g_id in group_ids:
        group_teams = [team for team in teams if team.group_id == g_id]

        for i in range(len(group_teams)):
            for j in range(i + 1, len(group_teams)):
                match = Match(
                    event_id=event_id,
                    group_id=g_id,
                    team1_id=group_teams[i].id,
                    team2_id=group_teams[j].id,
                    team1_score=None,
                    team2_score=None
                )
                db.session.add(match)
    db.session.commit()
    return redirect(url_for('select_match', event_id=event_id))

# CSOPORT EREDMÉNYEK LEKÉRDEZÉSE


def generate_group_data_overview(event_id, group_ids=[]):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    query = Match.query.filter(Match.event_id == event_id)
    if group_ids:
        query = query.filter(Match.group_id.in_(group_ids))

    matches = query.all()
    groups = Group.query.filter_by(event_id=event_id).all()
    team_stats = {}

    for match in matches:
        team1 = db.session.get(Team, match.team1_id)
        team2 = db.session.get(Team, match.team2_id)

        if team1 and team2:
            # Inicializáljuk a csapat statisztikáit, ha még nem léteznek
            if team1.id not in team_stats:
                team_stats[team1.id] = {
                    'name': team1.name, 'scored': 0, 'conceded': 0, 'points': 0, 'played': 0, 'wins': 0, 'losses': 0, 'draws': 0}
            if team2.id not in team_stats:
                team_stats[team2.id] = {
                    'name': team2.name, 'scored': 0, 'conceded': 0, 'points': 0, 'played': 0, 'wins': 0, 'losses': 0, 'draws': 0}

            # Ha a mérkőzés lejátszásra került, számoljuk a statisztikákat
            if match.team1_score is not None and match.team2_score is not None:
                team_stats[team1.id]['played'] += 1
                team_stats[team2.id]['played'] += 1

                team_stats[team1.id]['scored'] += match.team1_score
                team_stats[team1.id]['conceded'] += match.team2_score
                team_stats[team2.id]['scored'] += match.team2_score
                team_stats[team2.id]['conceded'] += match.team1_score

                # Sportágspecifikus pontozás
                if event.sport_type == 'football':  # Labdarúgás
                    if match.team1_score > match.team2_score:
                        team_stats[team1.id]['points'] += 3
                        team_stats[team1.id]['wins'] += 1
                        team_stats[team2.id]['losses'] += 1
                    elif match.team1_score < match.team2_score:
                        team_stats[team2.id]['points'] += 3
                        team_stats[team2.id]['wins'] += 1
                        team_stats[team1.id]['losses'] += 1
                    else:
                        team_stats[team1.id]['points'] += 1
                        team_stats[team2.id]['points'] += 1
                        team_stats[team1.id]['draws'] += 1
                        team_stats[team2.id]['draws'] += 1

                # Kézilabda és kosárlabda
                elif event.sport_type in ['handball', 'basketball']:
                    if match.team1_score > match.team2_score:
                        team_stats[team1.id]['points'] += 2
                        team_stats[team1.id]['wins'] += 1
                        team_stats[team2.id]['losses'] += 1
                    elif match.team1_score < match.team2_score:
                        team_stats[team2.id]['points'] += 2
                        team_stats[team2.id]['wins'] += 1
                        team_stats[team1.id]['losses'] += 1
                    elif event.sport_type == 'handball' and match.team1_score == match.team2_score:
                        # Csak kézilabdában lehet döntetlen
                        team_stats[team1.id]['points'] += 1
                        team_stats[team2.id]['points'] += 1
                        team_stats[team1.id]['draws'] += 1
                        team_stats[team2.id]['draws'] += 1

                elif event.sport_type == 'volleyball':  # Röplabda
                    if match.team1_score > match.team2_score:
                        team_stats[team1.id]['points'] += 2
                        team_stats[team1.id]['wins'] += 1
                        team_stats[team2.id]['losses'] += 1
                    elif match.team1_score < match.team2_score:
                        team_stats[team2.id]['points'] += 2
                        team_stats[team2.id]['wins'] += 1
                        team_stats[team1.id]['losses'] += 1

    group_data = {}
    for group in groups[:event.num_of_groups] if event.num_of_groups else groups:
        teams = Team.query.filter_by(group_id=group.id).all()
        team_data = []

        for team in teams:
            if team.id in team_stats:
                stats = team_stats[team.id]
                goal_difference = stats['scored'] - stats['conceded']
                team_data.append({
                    'team_id': team.id,
                    'team_name': stats['name'],
                    'played_games': stats['played'],
                    'scored_goals': stats['scored'],
                    'conceded_goals': stats['conceded'],
                    'goal_difference': goal_difference,
                    'points': stats['points'],
                    'wins': stats['wins'],
                    'losses': stats['losses'],
                    'draws': stats['draws'],
                })
        sorted_team_data = sorted(
            team_data, key=lambda x: (x['points'], x['goal_difference']), reverse=True
        )
        group_data[group.name] = sorted_team_data

    return group_data


@app.route('/groups_overview/<int:event_id>', methods=['GET', 'POST'])
@login_required
def groups_overview(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    groups = Group.query.filter_by(event_id=event_id).all()
    # Égetett érték!!!!
    group_ids = []
    for i in range(min(group.id for group in groups), max(group.id for group in groups[:event.num_of_groups])+1):
        group_ids.append(i)
    group_data = generate_group_data_overview(event_id, group_ids)
    group_data = dict(list(group_data.items())[:event.num_of_groups])

    return render_template('groups_overview.html', event=event, group_data=group_data)


def set_type_of_match(event_id, match_group_id=None):
    event = Event.query.get_or_404(event_id)
    match = Match.query.filter_by(
        group_id=match_group_id, event_id=event_id).first()
    groups = Group.query.filter_by(event_id=event_id)
    if event.event_type == "round_robin":
        return "round_robin"

    if event.event_type == "knockout":
        return "knockout"
    if match is not None:
        if match_group_id in range(min(group.id for group in groups), max(group.id for group in groups[:event.num_of_groups])+1):
            return "group_match"

        elif match_group_id == max(group.id for group in groups[:event.num_of_groups])+1:
            return "advance_to_knockout"
        else:
            return "knockout"
    return "preparation"


@app.route('/enter_result/<int:event_id>/<int:match_id>', methods=['GET', 'POST'])
@login_required
def enter_result(event_id, match_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    match = Match.query.get_or_404(match_id)
    group_id = match.group_id
    form = MatchResultForm(obj=match)
    if form.validate_on_submit():
        match.team1_score = form.team1_score.data
        match.team2_score = form.team2_score.data
        db.session.commit()
        flash('Az eredmény sikeresen elmentve!', 'success')
        return redirect(url_for('enter_result', event_id=event_id, match_id=match_id))
    if event.event_type == "group_knockout":
        type_of_match = set_type_of_match(event_id, match.group_id)
        return render_template('enter_result.html', event=event, match=match, form=form, type_of_match=type_of_match, group_id=group_id)
    if event.event_type == "round_robin":
        type_of_match = "round_robin"
        return render_template('enter_result_for_round_robin.html', event=event, match=match, form=form, type_of_match=type_of_match, group_id=group_id)
    if event.event_type == "knockout":
        type_of_match = "knockout"
        return render_template('enter_result.html', event=event, match=match, form=form, type_of_match=type_of_match, group_id=group_id)


# Az adott szakaszban minden mérkőzést lejátszottak-e?


def is_group_complete_by_group_id(event_id, group_id):
    matches = Match.query.filter_by(
        event_id=event_id).filter_by(group_id=group_id).all()
    stage_complete_checker = True
    for match in matches:
        if match.team1_score is None or match.team1_score is None:
            stage_complete_checker = False
    return stage_complete_checker


@app.route('/select_match/<int:event_id>', methods=['GET'])
@login_required
def select_match(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    matches = Match.query.filter_by(event_id=event_id).all()
    groups = Group.query.filter_by(event_id=event_id).all()
    group_checker_results = []
    group_ids = []
    for i in range(min(group.id for group in groups), max(group.id for group in groups[:event.num_of_groups])+1):
        group_ids.append(i)
    for group_id in group_ids:
        group_checker_result = is_group_complete_by_group_id(
            event_id, group_id)
        group_checker_results.append(group_checker_result)

    all_check_true = all(group_checker_results)

    group_matches = {}
    for group in groups:
        group_matches[group.name] = [
            match for match in matches if match.group_id == group.id
        ]
    group_matches = dict(list(group_matches.items())[:event.num_of_groups])
    existing_next_stage = Match.query.filter_by(
        event_id=event_id, group_id=max(group.id for group in groups[:event.num_of_groups])+1).all()
    return render_template('select_match.html', event=event, matches=matches, group_matches=group_matches, all_check_true=all_check_true, existing_next_stage=existing_next_stage)


@app.route('/advance_to_knockout/<int:event_id>')
@login_required
def advance_to_knockout(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    group_data = generate_group_data_overview(event_id)
    groups = Group.query.filter_by(event_id=event_id).all()

    # Meghatározzuk a következő csoport azonosítót
    knockout_first_group_id = max(
        group.id for group in groups[:event.num_of_groups]) + 1

    # Ellenőrizzük, hogy a kieséses mérkőzések már léteznek-e
    existing_knockout_matches = Match.query.filter_by(
        event_id=event_id, group_id=knockout_first_group_id).all()

    if not existing_knockout_matches:
        # Ha még nincsenek létrehozva, akkor most hozzuk létre őket
        knockout_matches = []

        for group, teams in group_data.items():
            knockout_matches.append(teams[0])
            knockout_matches.append(teams[1])

        for i in range(0, len(knockout_matches), 4):
            new_match = Match(
                event_id=event_id,
                group_id=knockout_first_group_id,
                team1_id=knockout_matches[i]['team_id'],
                team2_id=knockout_matches[i+3]['team_id'],
                team1_score=None,
                team2_score=None
            )
            db.session.add(new_match)

            new_match = Match(
                event_id=event_id,
                group_id=knockout_first_group_id,
                team1_id=knockout_matches[i+1]['team_id'],
                team2_id=knockout_matches[i+2]['team_id'],
                team1_score=None,
                team2_score=None
            )
            db.session.add(new_match)

        db.session.commit()

    knockout_matches = Match.query.filter_by(
        event_id=event_id, group_id=knockout_first_group_id).all()
    checker = is_group_complete_by_group_id(
        event_id, knockout_first_group_id)
    return redirect(url_for('list_knockout_stage_matches', event_id=event_id, group_id=knockout_first_group_id))


# Döntetlen ellenőrzés


def is_not_draw_in_group(event_id, group_id):
    matches = Match.query.filter_by(event_id=event_id, group_id=group_id).all()
    for match in matches:
        if match.team1_score is not None and match.team2_score is not None:
            if match.team1_score == match.team2_score:
                return False
    return True


@app.route('/list_knockout_stage_matches/<int:event_id>/<int:group_id>')
@login_required
def list_knockout_stage_matches(event_id, group_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    matches = Match.query.filter_by(
        event_id=event_id).filter_by(group_id=group_id)
    checker = is_group_complete_by_group_id(event_id, group_id)
    not_draw_in_group = is_not_draw_in_group(event_id, group_id)
    existing_next_stage = Match.query.filter_by(
        event_id=event_id, group_id=group_id+1).all()
    matches_count = matches.count()
    return render_template('list_knockout_stage_matches.html', event=event, matches=matches, checker=checker, group_id=group_id, not_draw_in_group=not_draw_in_group, existing_next_stage=existing_next_stage, matches_count=matches_count)

# kieséses szakasz mérkőzéseinek létrehozása


def create_knockout_matches(event_id, group_id, winners):
    # Új mérkőzések létrehozása párosítva a győzteseket
    for i in range(0, len(winners), 2):
        if i + 1 < len(winners):  # Győztesek párosítása
            new_match = Match(
                event_id=event_id,
                group_id=group_id,
                team1_id=winners[i].id,
                team2_id=winners[i+1].id,
                team1_score=None,
                team2_score=None
            )
            db.session.add(new_match)
    db.session.commit()


@app.route('/knockout_stage/<int:event_id>/<int:group_id>')
@login_required
def knockout_stage(event_id, group_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    prev_group_id = group_id

    # Az előző kör mérkőzéseinek lekérése
    previous_round_matches = Match.query.filter_by(
        event_id=event_id, group_id=prev_group_id).all()

    # Győztesek összegyűjtése
    winners = []
    for match in previous_round_matches:
        if match.team1_score is not None and match.team2_score is not None:
            if match.team1_score > match.team2_score:
                winners.append(match.team1)
            elif match.team2_score > match.team1_score:
                winners.append(match.team2)
    # Ellenőrzés: van-e végső győztes?
    if len(winners) == 1:
        final_winner = winners[0]
        event.is_ended = True
        db.session.commit()
        return render_template('final_winner.html', event=event, final_winner=final_winner, group_id=group_id)

    # Következő csoport azonosító meghatározása
    next_group_id = prev_group_id + 1

    # Ellenőrzés: léteznek-e már a következő kör mérkőzései?
    existing_matches = Match.query.filter_by(
        event_id=event_id, group_id=next_group_id).all()

    # Új mérkőzések létrehozása, ha még nem léteznek és van elég győztes
    if not existing_matches and len(winners) > 1:
        create_knockout_matches(event_id, next_group_id, winners)

    return redirect(url_for('list_knockout_stage_matches', event_id=event_id, group_id=next_group_id))


# Vesztesek listázása group_id alapján


def get_losers_by_group(event_id, group_id):
    matches = Match.query.filter_by(event_id=event_id, group_id=group_id).all()
    losers = []
    for match in matches:
        if match.team1_score > match.team2_score:
            losers.append(match.team2)
        elif match.team2_score > match.team1_score:
            losers.append(match.team1)
    return losers


@app.route('/event_result/<int:event_id>')
@login_required
def event_result(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    group_data = generate_group_data_overview(event_id)
    groups = Group.query.filter_by(event_id=event_id)
    out_from_groups = []

    team_count = db.session.query(func.count(
        Team.id)).filter_by(event_id=event_id).scalar()

    if event.event_type == "group_knockout":
        for group, teams in group_data.items():
            for team in teams[2:]:
                out_from_groups.append(team['team_id'])

        group_out_teams = Team.query.filter(Team.id.in_(out_from_groups)).all()

        # KÉT CSOPORT ESETÉN
    if event.event_type == "group_knockout":
        knockout_first_group_id = max(
            group.id for group in groups[:event.num_of_groups]) + 1
        if event.num_of_groups == 2:
            # Elődöntő kiesők
            losers_s = get_losers_by_group(event_id, knockout_first_group_id)
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id+1)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id+1).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2
            return render_template('event_result_for_group_knockout.html', event=event, group_out_teams=group_out_teams, losers_s=losers_s, final_winner=final_winner, final_loser=final_loser)

        # NÉGY CSOPORT ESETÉN
        if event.num_of_groups == 4:
            # Negyeddöntő kiesők
            losers_q = get_losers_by_group(event_id, knockout_first_group_id)
            # Elődöntő kiesők
            losers_s = get_losers_by_group(event_id, knockout_first_group_id+1)
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id+2)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id+2).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2
            return render_template('event_result_for_group_knockout.html', event=event, group_out_teams=group_out_teams, losers_q=losers_q, losers_s=losers_s, final_winner=final_winner, final_loser=final_loser)

            # NYOLC CSOPORT ESETÉN
        if event.num_of_groups == 8:
            # Nyolcaddöntő kiesők
            losers_r16 = get_losers_by_group(event_id, knockout_first_group_id)
            # Negyeddöntő kiesők
            losers_q = get_losers_by_group(event_id, knockout_first_group_id+1)
            # Elődöntő kiesők
            losers_s = get_losers_by_group(event_id, knockout_first_group_id+2)
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id+3)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id+3).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2
            return render_template('event_result_for_group_knockout.html', event=event, group_out_teams=group_out_teams, losers_r16=losers_r16, losers_q=losers_q, losers_s=losers_s, final_winner=final_winner, final_loser=final_loser)

    if event.event_type == "knockout":
        knockout_first_group_id = db.session.query(func.min(Match.group_id)).filter_by(
            event_id=event_id).scalar()
        if team_count == 32:
            # R32 kiesők
            losers_r32 = get_losers_by_group(event_id, knockout_first_group_id)
            # Nyolcaddöntő kiesők
            losers_r16 = get_losers_by_group(
                event_id, knockout_first_group_id+1)
            # Negyeddöntő kiesők
            losers_q = get_losers_by_group(event_id, knockout_first_group_id+2)
            # Elődöntő kiesők
            losers_s = get_losers_by_group(event_id, knockout_first_group_id+3)
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id+4)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id+4).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2

            return render_template('event_result_for_knockout.html', event=event, losers_r32=losers_r32, losers_r16=losers_r16, losers_q=losers_q, losers_s=losers_s, final_winner=final_winner, final_loser=final_loser)

        if team_count == 16:
            # Nyolcaddöntő kiesők
            losers_r16 = get_losers_by_group(
                event_id, knockout_first_group_id)
            # Negyeddöntő kiesők
            losers_q = get_losers_by_group(event_id, knockout_first_group_id+1)
            # Elődöntő kiesők
            losers_s = get_losers_by_group(event_id, knockout_first_group_id+2)
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id+3)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id+3).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2

            return render_template('event_result_for_knockout.html', event=event, losers_r16=losers_r16, losers_q=losers_q, losers_s=losers_s, final_winner=final_winner, final_loser=final_loser)

        if team_count == 8:
            # Negyeddöntő kiesők
            losers_q = get_losers_by_group(event_id, knockout_first_group_id)
            # Elődöntő kiesők
            losers_s = get_losers_by_group(event_id, knockout_first_group_id+1)
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id+2)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id+2).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2

            return render_template('event_result_for_knockout.html', event=event, losers_q=losers_q, losers_s=losers_s, final_winner=final_winner, final_loser=final_loser)

        if team_count == 4:

            # Elődöntő kiesők
            losers_s = get_losers_by_group(event_id, knockout_first_group_id)
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id+1)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id+1).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2

            return render_template('event_result_for_knockout.html', event=event, losers_s=losers_s, final_winner=final_winner, final_loser=final_loser)
        if team_count == 2:
            # Második helyezett
            final_loser = get_losers_by_group(
                event_id, knockout_first_group_id)
            # Végső győztes
            f_match = Match.query.filter_by(
                event_id=event_id, group_id=knockout_first_group_id).first()
            if f_match.team1_score > f_match.team2_score:
                final_winner = f_match.team1
            else:
                final_winner = f_match.team2

            return render_template('event_result_for_knockout.html', event=event, final_winner=final_winner, final_loser=final_loser)
    if event.event_type == "round_robin":
        event = Event.query.get_or_404(event_id)
        group = Group.query.filter_by(event_id=event_id).first()
        group_id = group.id
        group_ids = []
        group_ids.append(group_id)
        group_data = generate_group_data_overview(event_id, group_ids)
        group_data = dict(list(group_data.items()))
        final_rr_result = []
        for i, data in enumerate(group_data['RR']):
            final_rr_result.append(
                {'rank': i+1, 'name': data['team_name']})
        return render_template('event_result_for_round_robin.html', event=event, final_rr_result=final_rr_result)


##################
# EGYÉNI SPORTOK #
##################


@app.route('/add_participant/<int:event_id>', methods=['GET', 'POST'])
@login_required
def add_participant(event_id):
    form = AddParticipantForm()
    event = Event.query.get(event_id)
    if event.user_id != current_user.id:
        abort(403)
    participants = Participant.query.filter_by(event_id=event_id).all()
    form.event_id.data = event_id

    if form.validate_on_submit():
        name = form.name.data
        new_participant = Participant(
            name=name, event_id=event_id)
        db.session.add(new_participant)
        db.session.commit()

        return redirect(url_for('add_participant', event_id=event_id))

    return render_template('add_participant.html', form=form, event=event,  participants=participants)


@app.route('/delete_participant', methods=['POST'])
@login_required
def del_participant():
    participant_id = request.form.get('participant_id')
    event_id = request.form.get('event_id')
    participant = Participant.query.get(participant_id)
    db.session.delete(participant)
    db.session.commit()

    return redirect(url_for('add_participant', event_id=event_id))


@app.route('/add_individual_result/<int:event_id>/<int:participant_id>', methods=['GET', 'POST'])
@login_required
def add_individual_result(event_id, participant_id):
    form = AddIndividualResultForm()
    event = Event.query.get(event_id)
    if event.user_id != current_user.id:
        abort(403)
    participant = Participant.query.get_or_404(participant_id)

    if form.validate_on_submit():
        new_result = Individual_Result(
            event_id=event_id,
            participant_id=participant_id,
            score=form.score.data
        )
        db.session.add(new_result)
        db.session.commit()
        return redirect(url_for('list_participants', event_id=event_id))

    return render_template('add_individual_result.html', form=form, participant=participant, event_id=event_id, event=event)


@app.route('/participants/<int:event_id>', methods=['GET'])
@login_required
def list_participants(event_id):
    participants = Participant.query.filter_by(event_id=event_id).all()
    event = Event.query.get(event_id)
    if event.user_id != current_user.id:
        abort(403)

    participants_with_scores = []
    for participant in participants:
        latest_result = Individual_Result.query.filter_by(
            participant_id=participant.id, event_id=event_id).order_by(Individual_Result.id.desc()).first()

        if latest_result:
            participant.score = latest_result.score
        else:
            None

        participants_with_scores.append(participant)
    return render_template('list_participants.html', participants=participants_with_scores, event_id=event_id, event=event)


@app.route('/individual_final_rank/<int:event_id>', methods=['GET'])
@login_required
def individual_final_rank(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        abort(403)
    participants = Participant.query.filter_by(event_id=event_id).all()

    participants_with_scores = []
    for participant in participants:
        latest_result = Individual_Result.query.filter_by(
            participant_id=participant.id, event_id=event_id).order_by(Individual_Result.id.desc()).first()

        if latest_result:
            participant.score = latest_result.score
        else:
            participant.score = None

        participants_with_scores.append(participant)

    if event.sport_type in ['running', 'swimming']:
        participants_with_scores = sorted(
            [p for p in participants_with_scores if p.score is not None], key=lambda p: p.score)
    elif event.sport_type == 'throwing':
        participants_with_scores = sorted(
            [p for p in participants_with_scores if p.score is not None], key=lambda p: p.score, reverse=True)

    return render_template('individual_final_rank.html', participants=participants_with_scores, event=event)


@ app.route('/add_event/step1', methods=['GET', 'POST'])
@ login_required
def add_event_step1():
    form = AddEventForm1()
    individual_sports = ["running", "swimming", "jumping", "throwing"]
    if form.validate_on_submit():
        session['name'] = form.name.data
        session['date'] = form.date.data.strftime('%Y-%m-%d')
        session['sport_type'] = form.sport_type.data

        if session['sport_type'] in individual_sports:
            name = session["name"]
            # Átalakítjuk a stringet dátum objektummá
            date_str = session["date"]
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            sport_type = session["sport_type"]
            event_type = "individual_sport"
            num_of_groups = 0
            is_ended = False
            user_id = current_user.id
            new_event = Event(name, date, sport_type,
                              event_type, num_of_groups, is_ended, user_id)
            db.session.add(new_event)
            db.session.commit()
            return redirect(url_for('add_participant', event_id=new_event.id))

        return redirect(url_for('add_event_step2'))
    return render_template('add_event_step1.html', form=form)


@ app.route('/add_event/step2', methods=['GET', 'POST'])
@ login_required
def add_event_step2():
    form = AddEventForm2()
    if form.validate_on_submit():
        session['event_type'] = form.event_type.data

        if session['event_type'] == "round_robin" or session['event_type'] == "knockout":
            name = session["name"]
            # Átalakítjuk a stringet dátum objektummá
            date_str = session["date"]
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            sport_type = session["sport_type"]
            event_type = session['event_type']
            num_of_groups = 0
            is_ended = False
            user_id = current_user.id
            new_event = Event(name, date, sport_type,
                              event_type, num_of_groups, is_ended, user_id)
            db.session.add(new_event)
            db.session.commit()
            return redirect(url_for('add_team', event_id=new_event.id))
        return redirect(url_for('add_event_step3'))

    return render_template('add_event_step2.html', form=form)


@ app.route('/add_event/step3', methods=['GET', 'POST'])
@ login_required
def add_event_step3():
    form = AddEventForm3()
    if form.validate_on_submit():
        num_of_groups = form.num_of_groups.data
        name = session["name"]
        date_str = session["date"]
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        sport_type = session["sport_type"]
        event_type = session['event_type']
        is_ended = False
        user_id = current_user.id
        new_event = Event(name, date, sport_type,
                          event_type, num_of_groups, is_ended, user_id)
        db.session.add(new_event)
        db.session.commit()
        return redirect(url_for('add_team', event_id=new_event.id))

    return render_template('add_event_step3.html', form=form)


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


if __name__ == '__main__':
    app.run(debug=True)
