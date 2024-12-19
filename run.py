from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a real secret key
bcrypt = Bcrypt(app)

# Initialize the database
def init_db():
    with sqlite3.connect("users.db") as conn:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS transactions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        date TEXT NOT NULL,
                        type TEXT NOT NULL,  -- 'Income' or 'Expense'
                        category TEXT NOT NULL,
                        amount REAL NOT NULL
                    )''')
        conn.commit()

# Helper function to check if a user exists
def get_user_by_email(email):
    with sqlite3.connect("users.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()

@app.route('/')
def home():
        return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        if get_user_by_email(email):
            flash("Email already exists. Please use a different email.", "danger")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        with sqlite3.connect("users.db") as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashed_password))
            conn.commit()
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user_by_email(email)
        if user and bcrypt.check_password_hash(user[3], password):  # user[3] is the hashed password
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password.", "danger")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'Income'")
        total_income = cursor.fetchone()[0]

        cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'Expense'")
        total_expenses = cursor.fetchone()[0]

        total_balance = total_income - total_expenses

        cursor.execute("SELECT date, type, category, amount FROM transactions ORDER BY date DESC LIMIT 10")
        transactions = cursor.fetchall()

    return render_template(
        'dashboard.html',
        total_income=total_income,
        total_expenses=total_expenses,
        total_balance=total_balance,
        transactions=transactions
    )

@app.route('/add_income', methods=['GET', 'POST'])
def add_income():
    if request.method == 'POST':
        amount = request.form['amount']
        date = request.form['date']
        category = request.form['category']

        if not amount or not date or not category:
            return "All fields are required", 400

        with sqlite3.connect('users.db') as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO transactions (amount, date, type, category) VALUES (?, ?, ?, ?)",
                (amount, date, 'Income', category)
            )
            conn.commit()

        return redirect(url_for('dashboard'))

    return render_template('add_income.html')

@app.route('/add_expense', methods=['GET', 'POST'])
def add_expense():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        date = request.form['date']
        category = request.form['category']

        if not amount or not date or not category:
            return "All fields are required", 400

        with sqlite3.connect('users.db') as conn:
            cur = conn.cursor()

            cur.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'Income'")
            total_income = cur.fetchone()[0]

            cur.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'Expense'")
            total_expenses = cur.fetchone()[0]

            total_balance = total_income - total_expenses

            if total_balance < amount:
                flash("Balance is not enough to add this expense.", "danger")
                return redirect(url_for('add_expense'))

            cur.execute(
                "INSERT INTO transactions (amount, date, type, category) VALUES (?, ?, ?, ?)",
                (amount, date, 'Expense', category)
            )
            conn.commit()

        flash("Expense added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_expense.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
