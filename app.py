import hmac
import secrets
import sqlite3
from datetime import date
from functools import wraps
from pathlib import Path

import click
from flask import (
    Flask,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notebooks (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS calorie_goals (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    target INTEGER NOT NULL CHECK (target > 0)
);
CREATE TABLE IF NOT EXISTS meals (
    id INTEGER PRIMARY KEY,
    notebook_id INTEGER NOT NULL REFERENCES notebooks(id) ON DELETE CASCADE,
    meal_date TEXT NOT NULL,
    category TEXT NOT NULL,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0)
);
"""

MEAL_CATEGORIES = ("朝食", "昼食", "夕食", "間食")


def valid_date(value):
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=secrets.token_hex(32),
        DATABASE=str(Path(app.instance_path) / "meals.sqlite3"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            g.user = get_db().execute(
                "SELECT id, username FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if g.user is None:
                session.clear()

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("_csrf_token", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not supplied or not hmac.compare_digest(
                expected, supplied
            ):
                abort(400, description="CSRF token is missing or invalid.")

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.context_processor
    def inject_template_values():
        return {"csrf_token": get_csrf_token, "current_user": g.get("user")}

    @app.cli.command("init-db")
    def init_db_command():
        get_db().executescript(SCHEMA)
        click.echo("Database initialized.")

    @app.cli.command("seed-demo")
    def seed_demo_command():
        db = get_db()
        db.executescript(SCHEMA)
        usernames = ("a", "b", "c")
        existing = db.execute(
            "SELECT username FROM users WHERE username IN (?, ?, ?)", usernames
        ).fetchall()
        if existing:
            raise click.ClickException(
                "Demo users already exist; refusing to replace their passwords."
            )

        password_hashes = []
        for username in usernames:
            password = click.prompt(
                f"Password for demo user '{username}'", hide_input=True,
                confirmation_prompt=True,
            )
            if not password:
                raise click.ClickException("Passwords must not be empty.")
            password_hashes.append(generate_password_hash(password))

        db.executemany(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            zip(usernames, password_hashes),
        )
        db.commit()
        click.echo("Demo users a, b, and c created.")

    @app.route("/login", methods=("GET", "POST"))
    def login():
        if g.user is not None:
            return redirect(url_for("notebooks"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if user is None or not check_password_hash(user["password_hash"], password):
                return render_template(
                    "login.html", error="ユーザー名またはパスワードが違います。"
                ), 401

            session.clear()
            session["user_id"] = user["id"]
            session["_csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("notebooks"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def notebooks():
        rows = get_db().execute(
            "SELECT id, name FROM notebooks WHERE owner_id = ? ORDER BY id",
            (g.user["id"],),
        ).fetchall()
        return render_template("notebooks.html", notebooks=rows)

    @app.route("/notebooks/new", methods=("GET", "POST"))
    @login_required
    def create_notebook():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            if not name or len(name) > 100:
                return render_template(
                    "notebook_form.html",
                    error="ノート名は1〜100文字で入力してください。",
                    name=name,
                ), 400
            cursor = get_db().execute(
                "INSERT INTO notebooks (owner_id, name) VALUES (?, ?)",
                (g.user["id"], name),
            )
            get_db().commit()
            return redirect(
                url_for("notebook_detail", notebook_id=cursor.lastrowid)
            )
        return render_template("notebook_form.html", name="")

    @app.get("/notebooks/<int:notebook_id>")
    @login_required
    def notebook_detail(notebook_id):
        notebook = get_db().execute(
            "SELECT id, name FROM notebooks WHERE id = ? AND owner_id = ?",
            (notebook_id, g.user["id"]),
        ).fetchone()
        if notebook is None:
            abort(404)
        meal_date = request.args.get("date", "")
        query = request.args.get("q", "").strip()
        if meal_date and not valid_date(meal_date):
            abort(400, description="食事日はYYYY-MM-DDで指定してください。")
        meals = search_meals(notebook_id, meal_date, query)
        return render_template(
            "notebook.html", notebook=notebook, meals=meals,
            meal_date=meal_date, query=query, categories=MEAL_CATEGORIES,
        )

    @app.post("/notebooks/<int:notebook_id>/meals")
    @login_required
    def add_meal(notebook_id):
        db = get_db()
        notebook = db.execute(
            "SELECT id FROM notebooks WHERE id = ? AND owner_id = ?",
            (notebook_id, g.user["id"]),
        ).fetchone()
        if notebook is None:
            abort(404)
        meal_date = request.form.get("meal_date", "")
        category = request.form.get("category", "")
        name = request.form.get("name", "").strip()
        if not valid_date(meal_date) or category not in MEAL_CATEGORIES or not name:
            abort(400, description="食事日、区分、料理名を確認してください。")
        db.execute(
            "INSERT INTO meals (notebook_id, meal_date, category, name) VALUES (?, ?, ?, ?)",
            (notebook_id, meal_date, category, name),
        )
        db.commit()
        return redirect(url_for("notebook_detail", notebook_id=notebook_id))

    @app.route("/calorie-goal", methods=("GET", "POST"))
    @login_required
    def calorie_goal():
        db = get_db()
        if request.method == "POST":
            raw = request.form.get("target", "").strip()
            if not raw.isascii() or not raw.isdecimal() or len(raw) > 9 or int(raw) < 1:
                abort(400, description="目標摂取カロリーは正の整数で入力してください。")
            db.execute(
                "INSERT INTO calorie_goals (user_id, target) VALUES (?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET target = excluded.target",
                (g.user["id"], int(raw)),
            )
            db.commit()
            return redirect(url_for("calorie_goal"))
        goal = db.execute(
            "SELECT target FROM calorie_goals WHERE user_id = ?", (g.user["id"],)
        ).fetchone()
        return render_template("calorie_goal.html", goal=goal)

    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "error.html", title="リクエストを確認してください", message=error.description
        ), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html", title="ページが見つかりません", message="指定されたページはありません。"
        ), 404

    return app


def search_meals(notebook_id, meal_date, query):
    db = get_db()
    return db.execute(
        "SELECT meal_date, category, name FROM meals "
        "WHERE notebook_id = ? AND (? = '' OR meal_date = ?) "
        "AND instr(name, ?) > 0 ORDER BY meal_date DESC, id",
        (notebook_id, meal_date, meal_date, query),
    ).fetchall()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


if __name__ == "__main__":
    create_app().run()
