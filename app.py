import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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
    stocks = []
    symbol_groups = db.execute(
        "SELECT symbol, SUM(shares) FROM transactions WHERE user_id = ? GROUP BY symbol ORDER BY symbol;",
        user_id,
    )
    for group in symbol_groups:
        symbol = group["symbol"]
        shares = group["SUM(shares)"]
        data = lookup(symbol)
        name = data["name"]
        price = data["price"]
        total = price * shares
        stocks.append(
            {
                "symbol": symbol,
                "name": name,
                "shares": shares,
                "price": price,
                "total": total,
            }
        )
    select_balance = db.execute("SELECT cash FROM users WHERE id = ?;", user_id)
    balance = select_balance[0]["cash"]
    stocks_total = 0
    for stock in stocks:
        stocks_total += stock["total"]
    grand_total = stocks_total + balance

    return render_template(
        "index.html", rows=stocks, balance=balance, grand_total=grand_total
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    if request.form.get("symbol"):
        symbol = (request.form.get("symbol")).upper()
    else:
        return apology("Missing Symbol")

    if request.form.get("shares"):
        # Shares can be int or floats
        shares = request.form.get("shares")
        # If shares is not an int
        if not shares.isdigit():
            return apology("You cannot buy partial shares!")
        # If shares is not greater than 0
        if int(shares) <= 0:
            return apology("Shares must be greater than 0")
        # If shares is a valid int
        shares = int(shares)
    else:
        return apology("Missing Shares")

    data = lookup(symbol)
    if data:
        price = data["price"]
        cost = price * shares
        user_id = session["user_id"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?;", user_id)
        if cost > balance[0]["cash"]:
            return apology("Can't Afford")

        remaining = balance[0]["cash"] - cost
        db.execute(
            "INSERT INTO transactions (symbol, price, shares, user_id) VALUES (?, ?, ?, ?);",
            symbol,
            price,
            shares,
            user_id,
        )
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", remaining, user_id)
        flash("Bought!")
        return redirect("/")

    else:
        return apology("Invalid Symbol")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    rows = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY time;", user_id
    )
    return render_template("history.html", rows=rows)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    symbol = request.form.get("symbol")
    if symbol:
        data = lookup(symbol)
        if data:
            return render_template("quoted.html", data=data)
        else:
            return apology("Invalid Symbol", 400)
    else:
        return apology("Missing Symbol", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if not username:
        return apology("Pls fill out ur username")
    elif not password:
        return apology("Pls fill out ur password")
    elif not confirmation:
        return apology("Pls fill out ur password confirmation")

    username_exists = db.execute("SELECT * FROM users WHERE username = ?;", username)
    if username_exists:
        return apology("Username already exists!")

    elif password != confirmation:
        return apology("Passwords don't match!")

    hashed_pw = generate_password_hash(password, method="pbkdf2", salt_length=16)
    user_id = db.execute(
        "INSERT INTO users (username, hash) VALUES (?, ?);", username, hashed_pw
    )
    session["user_id"] = user_id
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    # Symbols owned by the user
    symbols = db.execute(
        "SELECT symbol, SUM(shares) FROM transactions WHERE user_id = ? GROUP BY symbol ORDER BY symbol;",
        user_id,
    )
    if request.method == "GET":
        return render_template("sell.html", symbols=symbols)

    # Post method
    if request.form.get("symbol"):
        symbol = (request.form.get("symbol")).upper()
    else:
        return apology("Missing Symbol")

    if request.form.get("shares"):
        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology("Shares must be Greater than 0")
    else:
        return apology("Missing Shares")

    data = lookup(symbol)
    if data:
        for s in symbols:
            if s["symbol"] == symbol:
                owned_shares = s["SUM(shares)"]
                if shares > owned_shares:
                    return apology("Too many shares!")

                balance = db.execute("SELECT cash FROM users WHERE id = ?;", user_id)
                current_price = data["price"]
                cost = current_price * shares
                remaining = balance[0]["cash"] + cost

                db.execute(
                    "INSERT INTO transactions (symbol, price, shares, user_id) VALUES (?, ?, ?, ?);",
                    symbol,
                    current_price,
                    shares * -1,
                    user_id,
                )
                db.execute(
                    "UPDATE users SET cash = ? WHERE id = ?;", remaining, user_id
                )
                flash("Sold!")
                return redirect("/")

        return apology("You don't own any share of this stock!")
    else:
        return apology("Invalid Symbol")


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """Add additional cash to account"""
    if request.method == "GET":
        return render_template("deposit.html")

    if request.form.get("amount"):
        amount = float(request.form.get("amount"))
        if amount <= 0:
            return apology("Amount must be greater than 0")
        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?;", user_id)
        updated_cash = cash[0]["cash"] + amount
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", updated_cash, user_id)
        flash("Deposited!")
        return redirect("/")

    return apology("Missing amount!")
