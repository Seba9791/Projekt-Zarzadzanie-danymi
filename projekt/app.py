import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SubmitField, DateField, IntegerField, FileField, TextAreaField, MultipleFileField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nieruchomosci.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'



db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class Nieruchomosc(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nazwa = db.Column(db.String(100), nullable=False)
    lokalizacja = db.Column(db.String(100), nullable=False)
    cena_dzienna = db.Column(db.Float, nullable=False)
    opis = db.Column(db.Text, nullable=True)
    image_file = db.Column(db.String(100), nullable=False, default='default.jpg')  # Upewnij się, że kolumna istnieje
    wynajmy = db.relationship('Wynajem', backref='nieruchomosc', lazy=True)
    opinions = db.relationship('Opinion', back_populates='nieruchomosc', lazy=True)
    zdjecia = db.relationship('Zdjecie', backref='nieruchomosc', lazy=True)


    def __repr__(self):
        return f"Nieruchomosc('{self.nazwa}', '{self.lokalizacja}')"
    def average_rating(self):
        if not self.opinions:
            return 0
        total_rating = sum(opinion.rating for opinion in self.opinions)
        return total_rating / len(self.opinions)
class Zdjecie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    nieruchomosc_id = db.Column(db.Integer, db.ForeignKey('nieruchomosc.id'), nullable=False)

    def __repr__(self):
        return f"Zdjecie('{self.filename}', '{self.nieruchomosc_id}')"

class PropertyForm(FlaskForm):
    nazwa = StringField('Nazwa', validators=[DataRequired()])
    lokalizacja = StringField('Lokalizacja', validators=[DataRequired()])
    cena_dzienna = FloatField('Cena dzienna', validators=[DataRequired()])
    opis = TextAreaField('Opis')
    zdjecia = MultipleFileField('Zdjęcia')


    opinions = db.relationship('Opinion', back_populates='user')
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone_number = db.Column(db.String(20))
    opinions = db.relationship('Opinion', back_populates='user')

    rentals = db.relationship('Rental', backref='user', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Wynajem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nieruchomosc_id = db.Column(db.Integer, db.ForeignKey('nieruchomosc.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data_od = db.Column(db.Date, nullable=False)
    data_do = db.Column(db.Date, nullable=False)
    kwota = db.Column(db.Float, nullable=False)

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddPropertyForm(FlaskForm):
    nazwa = StringField('Nazwa', validators=[DataRequired()])
    lokalizacja = StringField('Lokalizacja', validators=[DataRequired()])
    cena_dzienna = FloatField('Cena dzienna', validators=[DataRequired(), NumberRange(min=0)])
    image = FileField('Zdjęcie', validators=[DataRequired()])
    opis = StringField('Opis', validators=[DataRequired()])
    submit = SubmitField('Dodaj nieruchomość')


class Opinion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nieruchomosc_id = db.Column(db.Integer, db.ForeignKey('nieruchomosc.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    nieruchomosc = db.relationship('Nieruchomosc', back_populates='opinions')
    user = db.relationship('User', back_populates='opinions')

class OpinionForm(FlaskForm):
    rating = IntegerField('Ocena (1-5)', validators=[DataRequired(), NumberRange(min=1, max=5)])
    comment = TextAreaField('Komentarz', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Dodaj opinię')
class Rental(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nieruchomosc_id = db.Column(db.Integer, db.ForeignKey('nieruchomosc.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    user = db.relationship('User', back_populates='rentals')
    nieruchomosc = db.relationship('Nieruchomosc', back_populates='rentals')

User.rentals = db.relationship('Rental', back_populates='user')
Nieruchomosc.rentals = db.relationship('Rental', back_populates='nieruchomosc')
class RentForm(FlaskForm):
    start_date = DateField('Data rozpoczęcia', validators=[DataRequired()])
    end_date = DateField('Data zakończenia', validators=[DataRequired()])
    submit = SubmitField('Wynajmij')
class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    submit = SubmitField('Save Changes')
   
@app.route('/')
@app.route('/index')

def index():
    properties = Nieruchomosc.query.all()
    for property in properties:
        print(f"Image file for property {property.nazwa}: {property.image_file}")
    return render_template('index.html', properties=properties)

@app.route('/katalog')
@login_required
def katalog():
    nieruchomosci = Nieruchomosc.query.all()
    return render_template('property_list.html', nieruchomosci=nieruchomosci, title="Katalog Nieruchomości")

@app.route('/opinie', methods=['GET', 'POST'])
@login_required
def opinie():
    form = OpinionForm()
    if form.validate_on_submit():
        nieruchomosc_id = request.form.get('nieruchomosc_id')
        new_opinion = Opinion(
            nieruchomosc_id=nieruchomosc_id,
            user_id=current_user.id,
            rating=form.rating.data,
            comment=form.comment.data
        )
        db.session.add(new_opinion)
        db.session.commit()
        flash('Opinia dodana pomyślnie!', 'success')
        return redirect(url_for('opinie'))

    nieruchomosci = Nieruchomosc.query.all()
    return render_template('opinie.html', nieruchomosci=nieruchomosci, form=form)


@app.route('/opinie/<int:nieruchomosc_id>')
def opinie_nieruchomosc(nieruchomosc_id):
    nieruchomosc = Nieruchomosc.query.get_or_404(nieruchomosc_id)
    return render_template('opinie_nieruchomosc.html', nieruchomosc=nieruchomosc)
@app.route('/o_nas')
def o_nas():
    return render_template('o_nas.html')

@app.route('/kontakt', methods=['GET', 'POST'])
def kontakt():
    message_sent = False
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']

        message_sent = True
        flash('Twoja wiadomość została wysłana.', 'success')
        return render_template('kontakt.html', title='Kontakt', message_sent=message_sent)

    return render_template('kontakt.html', title='Kontakt', message_sent=message_sent)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if not current_user.is_admin:
        flash('Nie masz uprawnień do tej operacji', 'danger')
        return redirect(url_for('index'))
    
    form = PropertyForm()
    if form.validate_on_submit():
        nieruchomosc = Nieruchomosc(
            nazwa=form.nazwa.data,
            lokalizacja=form.lokalizacja.data,
            cena_dzienna=form.cena_dzienna.data,
            opis=form.opis.data
        )
        db.session.add(nieruchomosc)
        db.session.commit()

        for file in form.zdjecia.data:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            zdjecie = Zdjecie(filename=filename, nieruchomosc_id=nieruchomosc.id)
            db.session.add(zdjecie)
        
        db.session.commit()
        flash('Nieruchomość została dodana!', 'success')
        return redirect(url_for('katalog'))
    
    return render_template('add.html', title='Dodaj Nieruchomość', form=form)
@app.route('/property/<int:property_id>')
def property_detail(property_id):
    nieruchomosc = Nieruchomosc.query.get_or_404(property_id)
    return render_template('property_detail.html', title=nieruchomosc.nazwa, nieruchomosc=nieruchomosc)

@app.route('/edit/<int:property_id>', methods=['GET', 'POST'])
@login_required
def edit_property(property_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('katalog'))

    property = Nieruchomosc.query.get_or_404(property_id)
    form = AddPropertyForm(obj=property)
    if form.validate_on_submit():
        property.nazwa = form.nazwa.data
        property.lokalizacja = form.lokalizacja.data
        property.cena_dzienna = form.cena_dzienna.data
        property.opis = form.opis.data

        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                upload_folder = app.config['UPLOAD_FOLDER']
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                file.save(os.path.join(upload_folder, filename))
                property.image_file = filename

        db.session.commit()
        flash('Property updated successfully!', 'success')
        return redirect(url_for('katalog'))
    return render_template('edit.html', form=form, property=property)

@app.route('/delete/<int:property_id>', methods=['POST'])
@login_required
def delete_property(property_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('katalog'))

    property = Nieruchomosc.query.get_or_404(property_id)
    db.session.delete(property)
    db.session.commit()
    flash('Property deleted successfully!', 'success')
    return redirect(url_for('katalog'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('katalog')) 
        else:
            flash('Login failed. Check your username and/or password', 'danger')
    return render_template('login.html', form=form)
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_password,
                    first_name=form.first_name.data, last_name=form.last_name.data,
                    email=form.email.data, phone_number=form.phone_number.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/rent/<int:property_id>', methods=['GET', 'POST'])
@login_required
def rent_property(property_id):
    nieruchomosc = Nieruchomosc.query.get_or_404(property_id)
    form = RentForm()
    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data
        total_days = (end_date - start_date).days
        total_price = total_days * nieruchomosc.cena_dzienna
        rental = Rental(user_id=current_user.id, nieruchomosc_id=property_id, start_date=start_date, end_date=end_date, total_price=total_price)
        db.session.add(rental)
        db.session.commit()
        flash('Nieruchomość została wynajęta!', 'success')
        return redirect(url_for('user_panel'))
    return render_template('rent.html', title='Wynajmij nieruchomość', form=form, nieruchomosc=nieruchomosc)

@app.route('/user_panel')
@login_required
def user_panel():
    rentals = Rental.query.filter_by(user_id=current_user.id).all()
    return render_template('user_panel.html', rentals=rentals)
def create_admin_user():
    admin_username = 'admin'
    admin_password = 'admin'
    admin_email = 'admin@example.com'
    admin_first_name = 'Admin'
    admin_last_name = 'User'
    admin_phone_number = '123456789'

    user = User.query.filter_by(username=admin_username).first()
    if user is None:
        hashed_password = generate_password_hash(admin_password, method='scrypt')
        new_admin = User(username=admin_username, password=hashed_password, is_admin=True,
                         first_name=admin_first_name, last_name=admin_last_name, email=admin_email,
                         phone_number=admin_phone_number)
        db.session.add(new_admin)
        db.session.commit()

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.email = form.email.data
        current_user.phone_number = form.phone_number.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('user_panel'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.email.data = current_user.email
        form.phone_number.data = current_user.phone_number
    return render_template('edit_profile.html', title='Edit Profile', form=form)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True)
