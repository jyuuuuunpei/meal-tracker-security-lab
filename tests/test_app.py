import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from app import SCHEMA, create_app


class MealNotebookTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = str(Path(self.temp_dir.name) / "test.sqlite3")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": database,
            }
        )
        db = sqlite3.connect(database)
        try:
            db.executescript(SCHEMA)
            db.executemany(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                [
                    ("a", generate_password_hash("password-a")),
                    ("b", generate_password_hash("password-b")),
                    ("c", generate_password_hash("password-c")),
                ],
            )
            db.commit()
        finally:
            db.close()
        self.client = self.app.test_client()

    def tearDown(self):
        self.client = None
        self.app = None
        self.temp_dir.cleanup()

    def csrf_token(self, response):
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            response.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def login(self, username, password):
        page = self.client.get("/login")
        return self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(page),
                "username": username,
                "password": password,
            },
            follow_redirects=True,
        )

    def create_notebook(self, name):
        page = self.client.get("/notebooks/new")
        return self.client.post(
            "/notebooks/new",
            data={"csrf_token": self.csrf_token(page), "name": name},
            follow_redirects=True,
        )

    def test_owner_can_create_list_and_view_notebook(self):
        self.login("a", "password-a")
        response = self.create_notebook("Aのノート")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Aのノート", response.get_data(as_text=True))
        listing = self.client.get("/")
        self.assertIn("Aのノート", listing.get_data(as_text=True))

    def test_other_user_cannot_open_notebook_by_direct_url(self):
        self.login("a", "password-a")
        self.create_notebook("A private notebook")
        db = sqlite3.connect(self.app.config["DATABASE"])
        try:
            notebook_id = db.execute(
                "SELECT id FROM notebooks WHERE name = ?",
                ("A private notebook",),
            ).fetchone()[0]
        finally:
            db.close()

        self.client.post(
            "/logout",
            data={"csrf_token": self.csrf_token(self.client.get("/"))},
        )
        self.login("b", "password-b")
        response = self.client.get(f"/notebooks/{notebook_id}")

        self.assertEqual(response.status_code, 404)
        self.assertNotIn("A private notebook", response.get_data(as_text=True))

    def test_notebook_name_is_escaped(self):
        self.login("a", "password-a")
        response = self.create_notebook("<script>alert(1)</script>")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>", body)

    def test_login_and_notebook_creation_reject_missing_csrf(self):
        login_response = self.client.post(
            "/login", data={"username": "a", "password": "password-a"}
        )
        self.assertEqual(login_response.status_code, 400)

        self.login("a", "password-a")
        create_response = self.client.post(
            "/notebooks/new", data={"name": "No token"}
        )
        self.assertEqual(create_response.status_code, 400)

    def test_logout_requires_post_and_clears_session(self):
        self.login("a", "password-a")
        token = self.csrf_token(self.client.get("/"))
        response = self.client.post("/logout", data={"csrf_token": token})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_seed_demo_creates_hashed_accounts_and_refuses_duplicates(self):
        database = str(Path(self.temp_dir.name) / "seed.sqlite3")
        seed_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "seed-test-secret",
                "DATABASE": database,
            }
        )
        runner = seed_app.test_cli_runner()
        initialized = runner.invoke(args=["init-db"])
        self.assertEqual(initialized.exit_code, 0, initialized.output)

        seeded = runner.invoke(
            args=["seed-demo"],
            input=(
                "password-a\npassword-a\n"
                "password-b\npassword-b\n"
                "password-c\npassword-c\n"
            ),
        )
        self.assertEqual(seeded.exit_code, 0, seeded.output)
        db = sqlite3.connect(database)
        try:
            users = db.execute(
                "SELECT username, password_hash FROM users ORDER BY username"
            ).fetchall()
        finally:
            db.close()
        self.assertEqual([user[0] for user in users], ["a", "b", "c"])
        self.assertTrue(check_password_hash(users[0][1], "password-a"))
        self.assertNotEqual(users[0][1], "password-a")

        duplicate = runner.invoke(
            args=["seed-demo"],
            input=(
                "password-a\npassword-a\n"
                "password-b\npassword-b\n"
                "password-c\npassword-c\n"
            ),
        )
        self.assertNotEqual(duplicate.exit_code, 0)
        self.assertIn("already exist", duplicate.output)


if __name__ == "__main__":
    unittest.main()
