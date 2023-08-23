import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
import datetime

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    stock = db.execute("SELECT name, price, SUM(shares) AS shares FROM transactions WHERE user_id = ? GROUP BY name", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    i = 0
    total = 0
    for x in stock:
        total += stock[i]["price"] * stock[i]["shares"]
        i += 1

    total += cash

    return render_template("index.html", database = stock, cash = cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        number = request.form.get("shares")

        stock = lookup(symbol.upper())

        if not symbol:
            return apology("Please enter a symbol:(")

        if not stock:
            return apology("Invalid symbol:(")

        if int(number) <= 0:
            return apology("Shares must be a positive :(")

        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        name = stock["name"]
        price = round(stock["price"])
        total_price = int(number) * price
        time = datetime.datetime.now()

        if cash < total_price:
            return apology("Not enough cash :(")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price, user_id)
            flash("Bought :)")
            db.execute("INSERT INTO transactions(user_id, name, shares, price, type, time) VALUES (?, ?, ?, ?, ?, ?)", user_id, name, number, price, 'buy', time)

            return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    information = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)

    return render_template("history.html", information=information)

@app.route("/add_cash", methods=["GET", "POST"])
def add_cash():
    if request.method == "POST":
        user_id = session["user_id"]
        add = int(request.form.get("add"))

        if not add:
            return apology("Please enter a Add Cash:(")

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        new_cash = add + cash

        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        return redirect("/")

    else:
        return render_template("add.html")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Please enter a symbol:(")

        stock = lookup(symbol.upper())

        if not stock:
            return apology("Invalid symbol:(")

        return render_template("quoted.html", name = stock["name"], price = stock["price"])
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        if not username:
            return apology("Please enter a u:(")

        if not password:
            return apology("Please enter a password:(")

        if not confirmation:
            return apology("Please enter a confirm password:(")

        if password != confirmation:
            return apology("Confirm Password Not Equal Password")

        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
            return redirect('/')
        except:
            return apology("Username already been registered!")

    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        number = int(request.form.get("shares"))

        shares = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND name = ? GROUP BY name", user_id, symbol)[0]["shares"]
        price = db.execute("SELECT price FROM transactions WHERE user_id = ? AND name = ? GROUP BY name", user_id, symbol)[0]["price"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        time = datetime.datetime.now()

        if number < 1:
            return apology("Shares must be a positive :(")

        if shares < number:
            return apology("You don't have enough shares :(")
        else:
            total_sell = number * round(price)
            cash += total_sell
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, user_id)
            db.execute("INSERT INTO transactions(user_id, name, shares, price, type, time) VALUES (?, ?, ?, ?, ?, ?)", user_id, symbol, -number, price, 'sell', time)
            return redirect("/")

    else:
        user_id = session["user_id"]
        symbols = db.execute("SELECT name FROM transactions WHERE user_id = ? GROUP BY name", user_id)
        return render_template("sell.html", symbols=symbols)
        