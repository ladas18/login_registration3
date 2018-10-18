from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re
NAME_REGEX= re.compile(r'^[a-z][-a-z0-9]*\$') # Name regex is not good for first and first name
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "IMACXJ450#BD^7"
#.isalpha() is important

@app.route('/')
def index():
    if 'loggedIn' not in session:
        session['loggedIn'] = False
    else:
        session['loggedIn'] = True
    return render_template('index.html')

@app.route('/registered')
def register():
    return render_template('registered.html')

@app.route('/loggedin')
def login():
    if session['loggedIn'] == True:
        return render_template("login.html")
    else:
    return redirect('/')

@app.route('/register_proccess', methods=["POST"])
def registering():
    for key in request.form:
        if len(request.form[key]) < 1:
            print("Empty Field", key)
    if not NAME_REGEX.match(request.form['first_name']):
        flash("Your first name cannot contain any numbers or symbols", 'first_name')
    if not NAME_REGEX.match(request.form['last_name']):
        flash("Your last name cannot contain any numbers or symbols", 'last_name')
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!", 'email')
    if len(request.form['confirm_email']) != request.form['email']:
        flash("Your Email doesn't match",'confirm_email')
    if len(request.form['password']) < 8:
        flash(" Your password must have atleast 8 characters",'password')
    if len(request.form['confirm_password']) != request.form['password']:
        flash("Your Password doesn't match",'confirm_password')
    if '_flashes' in session.keys():
        return redirect("/")
    mysql = connectToMySQL('kentdb')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    query= "INSERT INTO users(first_name, last_name, email, password, created_at, updated_at) VALUES(%(first_name)s,%(last_name)s,%(email)s,%(password_hash)s,NOW(),NOW());"
    data = {
        'first_name':request.form['first_name'],
        'last_name':request.form['last_name'],
        'email':request.form['email'],
        'password_hash':pw_hash
    }
    mysql.query_db(query, data)
    return redirect('/registered')

@app.route('/login_proccess', methods=["POST"])
def loggin():
    mysql = connectToMySQL("simpledb")
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    if result:
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            session['loggedIn'] = True
            return redirect('/loggedin')
    flash("You could not be logged in")
    return redirect('/')


if __name__=="__main__":
    app.run(debug=True)
