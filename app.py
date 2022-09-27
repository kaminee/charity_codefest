from flask import Flask, render_template, flash, request, redirect, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from webforms import LoginForm, PostForm, UserForm, PasswordForm, NamerForm, SearchForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import uuid as uuid
import os
import json
import smtplib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# Secret Key!
app.config['SECRET_KEY'] = "my super secret key that no one is supposed to know"

db = SQLAlchemy(app)

# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# return User.query.filter_by(user_id=id).first()
#   return Users.query.get(int(user_id))

# Pass Stuff To Navbar
@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)


@app.route('/base')
def base():
    return render_template("navbar.html")


# Create Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # Check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Succesfull!!")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password - Try Again!")
        else:
            flash("That User Doesn't Exist! Try Again...")

    return render_template('login.html', form=form)


@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/engagement')
def engagement():
    return render_template('engagement.html')

# Create Logout Page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You Have Been Logged Out!  Thanks For Stopping By...")
    return redirect(url_for('login'))


# Create Admin Page
@app.route('/admin')
@login_required
def admin():
    id = current_user.id
    role_id = Users.query.filter_by(id=id).first()
    if role_id == 1:
        return render_template("admin.html")
    else:
        flash("Sorry you must be the Admin to access the Admin Page...")
        return redirect(url_for('dashboard'))


@app.route('/users-list', methods=['GET', 'POST'])
@login_required
def users_list():
    id = current_user.role_id
    name = None
    form = UserForm()
    if id == 1:
        our_users = Users.query.filter_by(status='approve').order_by(Users.date_added)
        return render_template("users_list.html",
                               our_users=our_users)
    else:
        flash("Sorry you must be the Admin to access the Admin Page...")
        return redirect(url_for('dashboard'))


@app.route('/approvers-list', methods=['GET', 'POST'])
@login_required
def approvers_list():
    id = current_user.role_id
    name = None
    form = UserForm()
    if id == 1:
        our_users = Users.query.filter_by(status='pending').order_by(Users.date_added)
        print("our users ", our_users)
        return render_template("approvers_list.html",
                               our_users=our_users)
    else:
        flash("Sorry you must be the Admin to access the Admin Page...")
        return redirect(url_for('dashboard'))


# Create a route decorator
@app.route('/')
def index():
    first_name = "John"
    stuff = "This is bold text"

    favorite_pizza = ["Pepperoni", "Cheese", "Mushrooms", 41]
    return render_template("index.html",
                           first_name=first_name,
                           stuff=stuff,
                           favorite_pizza=favorite_pizza)


# localhost:5000/user/John
@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    name = name_to_update
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.address = request.form['address']
        name_to_update.username = request.form['username']
        name_to_update.about_author = request.form['about_author']

        # Check for profile pic
        if request.files['profile_pic']:
            name_to_update.profile_pic = request.files['profile_pic']

            # Grab Image Name
            pic_filename = secure_filename(name_to_update.profile_pic.filename)
            # Set UUID
            pic_name = str(uuid.uuid1()) + "_" + pic_filename
            # Save That Image
            saver = request.files['profile_pic']

            # Change it to a string to save to db
            name_to_update.profile_pic = pic_name
            try:
                db.session.commit()
                saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
                flash("User Updated Successfully!")
                return render_template("user.html",
                                       form=form,
                                       name_to_update=name_to_update)
            except:
                flash("Error!  Looks like there was a problem...try again!")
                return render_template("user.html",
                                       form=form,
                                       name_to_update=name_to_update)
        else:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("user.html",
                                   form=form,
                                   name_to_update=name_to_update)
    else:
        return render_template("user.html",
                               form=form,
                               name_to_update=name_to_update,
                               id=id)

    return render_template('user.html', name=name)


# Create Name Page
@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None
    form = NamerForm()
    # Validate Form
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("Form Submitted Successfully!")

    return render_template("name.html",
                           name=name,
                           form=form)


@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    form.role_name.choices = [(rol.role_id, rol.role_name) for rol in Role.query.all()]

    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash the password!!!
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data,
                         address=form.address.data, role_id=form.role_name.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.role_name.data = ''
        form.address.data = ''
        form.password_hash.data = ''
        sender = 'matchlesscoder@gmail.com'
        receivers = 'kamineedbalkawade@gmail.com'

        message = """From: From Person <matchlesscoder@gmail.com>
        To: To Person <kamineedbalkawade@gmail.com>
        Subject: Welcome To StartYoungUK Charity Club
        Dear User,
         Welcome to  StartYoungUK Charity Club, Your request has been processed to the host.
         you will shortly get approval and then you will able to login to our club.
        """
        print(message)
        try:
            host = 'smtp.gmail.com'
            smtpObj = smtplib.SMTP(host, 587)
            smtpObj.ehlo()
            smtpObj.starttls()
            smtpObj.ehlo()
            smtpObj.login('matchlesscoder@gmail.com', 'matchless@2022')
            smtpObj.sendmail(sender, receivers, message)
            smtpObj.quit()
            print("Successfully sent email")
        except smtplib.SMTPException as s:
            error_code = s.smtp_code
            error_message = s.smtp_error
            print("Error: unable to send email", error_code, error_message)
        flash("User Added Successfully!")
    our_users = Users.query.order_by(Users.date_added)
    return render_template("add_user.html",
                           form=form,
                           name=name,
                           our_users=our_users)


# Update Database Record
@app.route('/update_status/<int:id>/<status>', methods=['GET', 'POST'])
@login_required
def update_status(id, status):
    print(id)
    print(status)
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)

    name_to_update.status = status

    try:
        print(name_to_update.status)
        db.session.merge(name_to_update)
        db.session.flush()
        db.session.commit()
        our_users = Users.query.filter_by(status='approve').order_by(Users.date_added)
        return render_template("users_list.html")
    except:
        flash("Error!  Looks like there was a problem...try again!")
        our_users = Users.query.filter_by(status='approve').order_by(Users.date_added)
        return render_template("users_list.html",
                               our_users=our_users)


# Update Database Record
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.address = request.form['address']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update, id=id)
        except:
            flash("Error!  Looks like there was a problem...try again!")
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update,
                                   id=id)
    else:
        return render_template("update.html",
                               form=form,
                               name_to_update=name_to_update,
                               id=id)


# Create Dashboard Page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UserForm()
    id = current_user.id
    users_asperlogin = db.session.query(Users.id, Users.name).order_by(Users.id).all()
    dates = db.session.query(Users.name, Users.date_added).order_by(Users.date_added).all()

    name_to_update = Users.query.get_or_404(id)

    over_time_added_users = []
    dates_label = []
    for uname, date_added in dates:
        dates_label.append(date_added.strftime("%m-%d-%y"))
        over_time_added_users.append(uname)
    return render_template("dashboard.html",
                           form=form,
                           over_time_added_users=json.dumps(over_time_added_users),
                           dates_label=json.dumps(dates_label),
                           users_asperlogin=json.dumps(users_asperlogin),
                           name_to_update=name_to_update,
                           id=id)


# Create Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    address = db.Column(db.String(120))
    about_author = db.Column(db.Text(), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    profile_pic = db.Column(db.String(), nullable=True)
    role_id = db.Column(db.Integer, nullable=True, default=3)
    status = db.Column(db.String(), nullable=True, default='pending')
    # Do some password stuff!
    password_hash = db.Column(db.String(128))

    # User Can Have Many Posts
    # posts = db.relationship('Posts', backref='poster')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Create A String
    def __repr__(self):
        return '<Name %r>' % self.name


class Role(db.Model, UserMixin):
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(20), nullable=False, unique=True)
# set FLASK_APP=db_table.py
# python -m flask run
