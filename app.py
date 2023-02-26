import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required

# Configure application
app = Flask(__name__)
# app.run(port=5000)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///mastery_log.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show profile and today's training plans"""
    return apology("TODO", 400)


@app.route("/about", methods=["GET", "POST"])
def about():
    """About page, users can see w/o logging in"""

    if request.method == "POST":
        return apology("TODO", 400)
    else:
        return render_template("about.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get username field from HTML form
        username = request.form.get("username")

        # Get password field from HTML form
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?;", (username, ))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], (password)):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User submitted register form
    if request.method == "POST" and "username" in request.form and "password" in request.form:

         # Get username field from HTML form
        username = request.form.get("username")

        # Get password field from HTML form
        password = request.form.get("password")

        if not username:
            return apology("must provide username and/or password", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide username and/or password", 400)

        # Search database for username that matches the username inputed
        accounts = db.execute("SELECT username FROM users WHERE username = ?;", (username, ))

        # If account already exists, return apology
        if accounts:
            return apology("username already taken", 400)

        # Make sure password contains at least one uppercase letter, one number, and a special character
        u, p, d = 0, 0, 0
        specialchar = "!@#$%^&*()-+?_=,<>/"
        digits = "0123456789"
        capitalalphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        pw_len = len(password)
        if pw_len < 8:
            return apology("password must be at least 8 characters long, contain one uppercase letter, one number, and a special character", 400)

        for i in password:

            # counting uppercase alphabets
            if (i in capitalalphabets):
                u += 1

            # counting digits
            if (i in digits):
                d += 1

            # counting special chars
            if (i in specialchar):
                p += 1

        # checking if password meets requirements
        if (u < 1 or p < 1 or d < 1):
            return apology("password must be at least 8 characters long, contain one uppercase letter, one number, and a special character", 400)

        # Check if password and confirmation of password matches
        if password != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Generate hash of password and input it in users table
        else:
            hash = generate_password_hash(password)
            db.execute("INSERT INTO users(username, hash) VALUES (?);", (username, hash))

            # Redirect user to home page
            return redirect("/")

    # Redirect user to register form
    return render_template("register.html")


@app.route("/calendar", methods=["GET", "POST"])
def calendar():
    """ User can plan their training/climbing in calendar, add important dates """
    return apology("TODO", 400)


@app.route("/training", methods=["GET", "POST"])
def training():
    """ User can plan their training cycles here, add exercises... """
    return apology("TODO", 400)


@app.route("/climbing", methods=["GET", "POST"])
def climbing():
    """ User can plan their climbing sessions here, write goals/projects, log climbs sent... """
    return apology("TODO", 400)

@app.route("/account", methods=["GET", "POST"])
def account():
    """ User can edit their account, view their goals... """
    return apology("TODO", 400)