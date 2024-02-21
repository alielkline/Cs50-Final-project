import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username")

        elif not request.form.get("password"):
            return apology("must provide password")

        elif not request.form.get("confirmation"):
            return apology("must confirm password")

        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords doesnt match")

        user_exists = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if user_exists:
            return apology("Username already taken")

        unhashed_password = request.form.get("password")
        username = request.form.get("username")
        hashed_password = generate_password_hash(unhashed_password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        return redirect("/login")

    else:
        return render_template("register.html")

@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        password = db.execute("SELECT hash FROM users WHERE id=:user_id", user_id=session["user_id"])[0]["hash"]
        if not check_password_hash(password, request.form.get("old_password")):
            return apology("Wrong password")
        else:
            if request.form.get("new_password") == request.form.get("confirmation"):
                hashed_new_password = generate_password_hash(request.form.get("new_password"))
                db.execute("UPDATE users SET hash=:password WHERE id = :user_id",
                           password=hashed_new_password, user_id=session["user_id"])
            return redirect("/")
    else:
        return render_template("password.html")
