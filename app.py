from flask import Flask, render_template, request, redirect
from models import User, Entry, db
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, logout_user

app = Flask(__name__)
app.config["SECRET_KEY"] = "secretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///entry.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Get rid of deprecation warning
db.init_app(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return redirect('/login')

@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
    if request.method == 'POST':
        key = request.form['set_key']
        value = request.form['set_value']
        new_entry = Entry(key=key, user_id=current_user.id, value=value)

        duplicate = Entry.query.filter_by(key=key, user_id=current_user.id).first()
        if duplicate is not None:
            return render_template('index.html', message="That key has been entered already.", entry=None, key=None)
        
        try:
            db.session.add(new_entry)
            db.session.commit()
            message = "<Key: %s Value: %s> added to database succesfully." % (key, value)
            return render_template('index.html', message=message, entry=None, key=None)
        except:
            return "Error adding entry to the database."    
    else:
        result = None
        key = request.args.get('get_key')
        if key is not None:
            result = Entry.query.filter_by(user_id=current_user.id, key=key).first()

        return render_template('index.html', message=None, key=key, entry=result)
    

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user is None or not user.is_valid_password(password):
            return render_template('auth/login.html', message="Incorrect username or password.")
            
            
        login_user(user)
        return redirect('/')
    else:
        return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('auth/register.html', message='User already exists.')
        
        user = User(username=username, password=password)
        user.secure_password(password)

        try:
            db.session.add(user)
            db.session.commit()

            login_user(user)
            return redirect('/')
        except:
            return "Error adding entry to the database."

    return render_template('auth/register.html')


if __name__ == "__main__":
    app.run()