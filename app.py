from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt

from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin


app = Flask(__name__)
app.config['SECRET_KEY'] = '8c095844781d3a9c3c13ae33c96c59ff435530c91e7e77d837a63256527c1b4f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)  # Initialize Flask-Login

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    entries = db.relationship('PasswordEntry', backref='user', lazy=True)

    def is_active(self):
        # You can customize this method based on your logic
        return True

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PasswordForm(FlaskForm):
    website = StringField('Website', validators=[DataRequired(), Length(max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=120)])
    submit = SubmitField('Save Changes')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)  # Move this line here
            return redirect(url_for('dashboard', username=user.username))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/dashboard/<username>')
@login_required
def dashboard(username):
    user = User.query.filter_by(username=current_user.username).first()
    entries = PasswordEntry.query.filter_by(user_id=user.id).all()
    form = PasswordForm()
    return render_template('dashboard.html', username=username, entries=entries, form=form)


@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    form = PasswordForm()
    if form.validate_on_submit():
        user = current_user  # Use current_user instead of accessing session directly
        entry = PasswordEntry(website=form.website.data, username=form.username.data, password=form.password.data, user=user)
        db.session.add(entry)
        db.session.commit()
        flash('New entry added successfully.', 'success')
    return redirect(url_for('dashboard', username=current_user.username))


@app.route('/edit_entry/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    form = PasswordForm()
    if form.validate_on_submit():
        entry.website = form.website.data
        entry.username = form.username.data
        entry.password = form.password.data
        db.session.commit()
        flash('Entry updated successfully.', 'success')
        return redirect(url_for('dashboard', username=current_user.username))
    elif request.method == 'GET':
        form.website.data = entry.website
        form.username.data = entry.username
        form.password.data = entry.password
    return render_template('edit_entry.html', form=form)

@app.route('/remove_entry/<int:entry_id>', methods=['POST'])
@login_required
def remove_entry(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    flash('Entry removed successfully.', 'success')
    return redirect(url_for('dashboard', username=current_user.username))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
