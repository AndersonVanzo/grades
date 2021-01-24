import os.path
import pusher
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_login import LoginManager, login_user, logout_user, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.widgets import TextArea
from wtforms.validators import InputRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from random import randint

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'grades'
app.config['DEBUG'] = True

pusher_client = pusher.Pusher(
    app_id="1141719",
    key="ecdbd13504eee32aee84",
    secret="1b2deb39683fef455926",
    cluster="us2",
    ssl=True
)

db = SQLAlchemy(app)

lm = LoginManager(app)
lm.login_view = 'login'

numbers = []


# verifica o tipo de usuario logado (se é professor ou aluno)
def login_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return lm.unauthorized()
            if (current_user.urole != role) and (role != "ANY"):
                return lm.unauthorized()
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


@lm.user_loader
def user_loader(user_id):
    return Users.query.get(user_id)


# tabela dos usuarios
class Users(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    name = db.Column(db.String)
    urole = db.Column(db.String)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def get_urole(self):
        return self.urole

    def __init__(self, username, email, password, name, urole):
        self.username = username
        self.email = email
        self.password = password
        self.name = name
        self.urole = urole


# tabela das provas
class Tests(db.Model):
    __tablename__ = 'tests'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String)
    description = db.Column(db.String)
    number = db.Column(db.Integer)

    def __init__(self, title, description, number):
        self.title = title
        self.description = description
        self.number = number


# tabela das perguntas
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String)
    number = db.Column(db.Integer)

    def __init__(self, description, number):
        self.description = description
        self.number = number


# tabela das resposta
class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    answer = db.Column(db.String)
    number = db.Column(db.Integer)

    def __init__(self, name, answer, number):
        self.name = name
        self.answer = answer
        self.number = number


# tabela pra saber quem ja respondeu
class Students(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    number = db.Column(db.Integer)
    answered = db.Column(db.Integer)
    revised = db.Column(db.Integer)
    grade = db.Column(db.Integer)

    def __init__(self, name, number, answered, revised, grade):
        self.name = name
        self.number = number
        self.answered = answered
        self.revised = revised
        self.grade = grade


# tabela do chat
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    message = db.Column(db.String)

    def __init__(self, name, message):
        self.name = name
        self.message = message


# formulario de login
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])


# formulario de cadastro
class RegisterForm(FlaskForm):
    name = StringField('name', validators=[InputRequired()])
    username = StringField('username', validators=[InputRequired()])
    email = StringField('email', validators=[InputRequired(), Email()])
    password = PasswordField('password', validators=[InputRequired()])


# formulario de nova prova
class NewTest(FlaskForm):
    title = StringField('title', validators=[InputRequired()])
    description = StringField('description', widget=TextArea(), validators=[InputRequired()])


# formulario de nova pergunta
class NewQuestion(FlaskForm):
    description = StringField('description', widget=TextArea(), validators=[InputRequired()])


# formulario de resposta
class AnswerForm(FlaskForm):
    answer = StringField('answer', widget=TextArea(), validators=[InputRequired()])


class ReviseForm(FlaskForm):
    txt = StringField('txt')


class NewMessage(FlaskForm):
    message = StringField('message', validators=[InputRequired()])


# pagina de login
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.form:
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                if user.urole == "teacher":
                    return redirect(url_for('teacher'))
                else:
                    return redirect(url_for('student'))
        else:
            flash("Invalid Login")
    return render_template('login.html', form=form)


@app.route('/signup')
def signup():
    return render_template('cadastro.html')


# pagina de cadastro de professor
@app.route('/signupteacher', methods=["GET", "POST"])
def signupteacher():
    form = RegisterForm()
    if request.form:
        # criptografa a senha
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = Users(username=form.username.data, password=hashed_password, email=form.email.data,
                         name=form.name.data, urole="teacher")
        db.session.add(new_user)
        db.session.commit()

        user = Users.query.filter_by(username=new_user.username).first()
        login_user(user)
        return redirect(url_for('teacher'))

    return render_template('cadastroprofessor.html', form=form)


# pagina de cadastro de aluno
@app.route('/signupstudent', methods=["GET", "POST"])
def signupstudent():
    form = RegisterForm()
    if request.form:
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = Users(username=form.username.data, password=hashed_password, email=form.email.data,
                         name=form.name.data, urole="student")
        db.session.add(new_user)
        db.session.commit()

        user = Users.query.filter_by(username=new_user.username).first()
        login_user(user)
        return redirect(url_for('student'))

    return render_template('cadastroaluno.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/teacher')
@login_required(role="teacher")  # ! apenas professor pode acessar
def teacher():
    tests = Tests.query.all()
    return render_template('professor.html', name=current_user.name, tests=tests)


@app.route('/new', methods=['GET', 'POST'])
@login_required(role="teacher")
def new():
    testform = NewTest()
    questionform = NewQuestion()

    f = request.form
    descriptions = []
    desccount = 0
    for key in f.keys():
        for value in f.getlist(key):
            if key == 'title':
                title = value
            if key == 'description':
                descriptions.append(value)
                desccount += 1

    while True:
        count = 0
        temp = randint(0, 1000)
        for i in range(len(numbers)):
            if temp == numbers[i]:
                count += 1
        if count == 0:
            break
    number = temp
    numbers.append(number)

    if f:
        new_test = Tests(title=title, description=descriptions[0], number=number)
        db.session.add(new_test)
        db.session.commit()

        for x in range(len(descriptions)):
            if x != 0:
                new_question = Question(description=descriptions[x], number=number)
                db.session.add(new_question)
                db.session.commit()

        return redirect(url_for('teacher'))

    return render_template('novo.html', name=current_user.name, testform=testform, questionform=questionform)


@app.route('/student')
@login_required(role="student")
def student():
    tests = Tests.query.all()
    students = Students.query.filter_by(name=current_user.name)
    return render_template('aluno.html', name=current_user.name, tests=tests, students=students)


@app.route('/test/<number>', methods=['GET', 'POST'])
@login_required(role="student")
def test(number):
    wtest = Tests.query.filter_by(number=number).first()
    questions = Question.query.filter_by(number=number).all()
    form = AnswerForm()
    f = request.form

    if f:
        for key in f.keys():
            for value in f.getlist(key):
                newanswer = Answer(name=current_user.name, answer=value, number=number)
                db.session.add(newanswer)
                db.session.commit()

        db.session.commit()

        newstudent = Students(name=current_user.name, number=number, answered=1, revised=0, grade=0)
        db.session.add(newstudent)
        db.session.commit()
        return redirect(url_for('student'))

    return render_template('test.html', name=current_user.name, number=number, test=wtest, questions=questions,
                           form=form)


@app.route('/view/<number>')
@login_required(role="teacher")
def view(number):
    wtest = Tests.query.filter_by(number=number).first()
    questions = Question.query.filter_by(number=number).all()
    return render_template('view.html', name=current_user.name, number=number, test=wtest, questions=questions)


@app.route('/answers/<number>')
@login_required(role="teacher")
def answers(number):
    students = Students.query.filter_by(number=number).all()
    return render_template('answers.html', name=current_user.name, students=students, number=number)


@app.route('/revise/<name>/<number>', methods=['GET', 'POST'])
@login_required(role="teacher")
def revise(name, number):
    wtest = Tests.query.filter_by(number=number).first()
    questions = Question.query.filter_by(number=number).all()
    wanswers = Answer.query.filter_by(name=name, number=number).all()
    tstudent = Students.query.filter_by(number=number, name=name).first()
    form = ReviseForm()
    f = request.form
    grade = 0

    if f:
        for key in f.keys():
            for value in f.getlist(key):
                if key == 'correct':
                    grade += 1

        grade = round(grade * (10 / len(wanswers)), 2)

        tstudent.revised = 1
        tstudent.grade = grade
        db.session.commit()

        return redirect(url_for('teacher'))

    if tstudent.revised == 1:
        return render_template('alreadyrevised.html', name=current_user.name)
    else:
        return render_template('revise.html', name=current_user.name, sname=name, number=number, test=wtest,
                               questions=questions, answers=wanswers, form=form)


@app.route('/chat', methods=['GET', 'POST'])
@login_required()
def chat():
    form = NewMessage()
    if request.form:
        new_message = Message(name=current_user.name, message=form.message.data)
        db.session.add(new_message)
        db.session.commit()

        pusher_client.trigger('my-channel', 'my-event', {'name': current_user.name, 'message': form.message.data})

    amessages = Message.query.all()
    return render_template('chat.html', name=current_user.name, messages=amessages, form=form)


if __name__ == '__main__':
    app.run()
