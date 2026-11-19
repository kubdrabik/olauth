from pathlib import Path
import tempfile
import unittest

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from flask import Flask, render_template_string

import olauth


class FlaskEngineTests(unittest.TestCase):
    def _create_app(self, *, auto_login_on_signup=True, rate_limit=15):
        app = Flask(__name__)
        olauth.init(
            app,
            db=":memory:",
            redirect_to="/",
            auto_login_on_signup=auto_login_on_signup,
            rate_limit=rate_limit,
        )

        @app.route("/")
        def home():
            user = olauth.current_user()
            return render_template_string(
                "{{ current_user.email if current_user else 'guest' }}|{{ u }}",
                u=user["email"] if user else "none",
            )

        @app.route("/dashboard")
        @olauth.login_required
        def dashboard():
            user = olauth.current_user()
            return f"dashboard:{user['email']}:{user['id']}"

        return app

    def tearDown(self):
        olauth.olauth.db.close()

    def test_signup_autologin_protected_route_and_logout(self):
        app = self._create_app()
        client = app.test_client()

        # Logged out: HTML access to protected route redirects to /login?next=...
        res = client.get("/dashboard?tab=stats", headers={"Accept": "text/html"})
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login?next=%2Fdashboard%3Ftab%3Dstats", res.headers["Location"])

        # Logged out: JSON access to protected route returns 401
        res_json = client.get("/dashboard", headers={"Accept": "application/json"})
        self.assertEqual(res_json.status_code, 401)
        self.assertIn("error", res_json.get_json())

        # GET /signup renders form with security headers
        get_signup = client.get("/signup")
        self.assertEqual(get_signup.status_code, 200)
        self.assertEqual(get_signup.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(get_signup.headers.get("X-Content-Type-Options"), "nosniff")

        # Short password fails validation
        bad_pw = client.post("/signup", data={"email": "a@example.com", "password": "short"})
        self.assertEqual(bad_pw.status_code, 400)
        self.assertIn(b"at least 8 characters", bad_pw.data)

        # Successful signup logs user in and sets HttpOnly cookie
        signup_res = client.post(
            "/signup?next=/dashboard",
            data={"email": "Alice@Example.com", "password": "strongpassword123"},
        )
        self.assertEqual(signup_res.status_code, 302)
        self.assertTrue(signup_res.headers["Location"].endswith("/dashboard"))
        set_cookie = signup_res.headers.get("Set-Cookie", "")
        self.assertIn("olauth_session=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Lax", set_cookie)

        # Duplicate signup fails with 400
        client2 = app.test_client()
        dup_res = client2.post(
            "/signup",
            data={"email": "alice@example.com", "password": "strongpassword123"},
        )
        self.assertEqual(dup_res.status_code, 400)
        self.assertIn(b"already exists", dup_res.data)

        # Protected route & template context work while authenticated
        home_res = client.get("/")
        self.assertEqual(home_res.status_code, 200)
        self.assertEqual(home_res.data.decode(), "alice@example.com|alice@example.com")

        dash_res = client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn("dashboard:alice@example.com:", dash_res.data.decode())

        # Logout clears session in DB and invalidates access
        logout_res = client.get("/logout")
        self.assertEqual(logout_res.status_code, 302)
        self.assertTrue(logout_res.headers["Location"].endswith("/login"))

        after_logout = client.get("/dashboard")
        self.assertEqual(after_logout.status_code, 302)
        self.assertIn("/login", after_logout.headers["Location"])

    def test_login_next_redirect_open_redirect_protection_csrf_and_rate_limit(self):
        app = self._create_app(auto_login_on_signup=False, rate_limit=3)
        client = app.test_client()

        # Signup with auto_login_on_signup=False redirects to /login without session cookie
        signup_res = client.post(
            "/signup",
            data={"email": "bob@example.com", "password": "supersecret99"},
        )
        self.assertEqual(signup_res.status_code, 302)
        self.assertTrue(signup_res.headers["Location"].endswith("/login"))
        self.assertNotIn("olauth_session=", signup_res.headers.get("Set-Cookie", ""))

        # Cross-origin POST is blocked
        csrf_res = client.post(
            "/login",
            data={"email": "bob@example.com", "password": "supersecret99"},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(csrf_res.status_code, 403)

        # Wrong password triggers 401 and counts toward rate limit
        for _ in range(3):
            fail_res = client.post(
                "/login",
                data={"email": "bob@example.com", "password": "wrongpassword"},
            )
            self.assertEqual(fail_res.status_code, 401)
            self.assertIn(b"Invalid email or password", fail_res.data)

        # 4th attempt is rate-limited
        limited_res = client.post(
            "/login",
            data={"email": "bob@example.com", "password": "supersecret99"},
        )
        self.assertEqual(limited_res.status_code, 429)

        # Reset via new client IP simulation (using REMOTE_ADDR) and test open-redirect blocking
        login_res = client.post(
            "/login?next=//evil.com",
            data={"email": "bob@example.com", "password": "supersecret99"},
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
        )
        self.assertEqual(login_res.status_code, 302)
        self.assertEqual(login_res.headers["Location"], "/")

        # Valid ?next=/dashboard works
        client.post("/logout")
        login_next = client.post(
            "/login?next=/dashboard",
            data={"email": "bob@example.com", "password": "supersecret99"},
            environ_base={"REMOTE_ADDR": "10.0.0.6"},
        )
        self.assertEqual(login_next.status_code, 302)
        self.assertTrue(login_next.headers["Location"].endswith("/dashboard"))

        # POST /logout clears session
        post_logout = client.post("/logout")
        self.assertEqual(post_logout.status_code, 302)
        self.assertEqual(client.get("/dashboard").status_code, 302)

    def test_flask_json_auth_and_already_authenticated_redirects(self):
        app = self._create_app()
        client = app.test_client()

        res = client.post(
            "/signup",
            json={"email": "json@example.com", "password": "strongpassword123"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.get_json()["user"]["email"], "json@example.com")

        # Already authenticated GET /login and GET /signup redirect to redirect_to
        self.assertEqual(client.get("/login").status_code, 302)
        self.assertEqual(client.get("/signup").status_code, 302)

        out = client.post("/logout", headers={"Accept": "application/json"})
        self.assertEqual(out.status_code, 200)
        self.assertEqual(out.get_json()["message"], "Logged out")

        login_json = client.post(
            "/login",
            json={"email": "json@example.com", "password": "strongpassword123"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(login_json.status_code, 200)
        self.assertEqual(login_json.get_json()["user"]["email"], "json@example.com")

    def test_flask_email_verification_code_flow(self):
        sent_codes = []
        app = Flask(__name__)
        olauth.init(
            app,
            db=":memory:",
            redirect_to="/",
            send_verification_code=lambda email, code: sent_codes.append((email, code)),
        )

        @app.route("/dashboard")
        @olauth.login_required
        def dashboard():
            return f"verified:{olauth.current_user()['email']}"

        client = app.test_client()

        # Signup redirects to /verify without setting a session cookie yet
        signup_res = client.post(
            "/signup?next=/dashboard",
            data={"email": "Verify@Example.com", "password": "strongpassword123"},
        )
        self.assertEqual(signup_res.status_code, 302)
        self.assertIn("/verify?email=verify%40example.com&next=%2Fdashboard", signup_res.headers["Location"])
        self.assertNotIn("olauth_session=", signup_res.headers.get("Set-Cookie", ""))
        self.assertEqual(len(sent_codes), 1)
        first_email, first_code = sent_codes[0]
        self.assertEqual(first_email, "verify@example.com")
        self.assertEqual(len(first_code), 6)

        # Trying to log in before verifying issues a fresh code and redirects to /verify
        login_res = client.post(
            "/login",
            data={"email": "verify@example.com", "password": "strongpassword123"},
        )
        self.assertEqual(login_res.status_code, 302)
        self.assertIn("/verify?email=verify%40example.com", login_res.headers["Location"])
        self.assertEqual(len(sent_codes), 2)
        latest_code = sent_codes[-1][1]

        # JSON login before verifying returns 403 with redirect_to
        login_json = client.post(
            "/login",
            json={"email": "verify@example.com", "password": "strongpassword123"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(login_json.status_code, 403)
        self.assertIn("/verify", login_json.get_json()["redirect_to"])
        latest_code = sent_codes[-1][1]

        # GET /verify renders the code entry form
        get_verify = client.get("/verify?email=verify@example.com&next=/dashboard")
        self.assertEqual(get_verify.status_code, 200)
        self.assertIn(b"Verify your email", get_verify.data)

        # Wrong code returns 400
        wrong_code = "000000" if latest_code != "000000" else "999999"
        bad_verify = client.post(
            "/verify?email=verify@example.com&next=/dashboard",
            data={"code": wrong_code},
        )
        self.assertEqual(bad_verify.status_code, 400)
        self.assertIn(b"Invalid or expired verification code", bad_verify.data)

        # Correct code verifies, sets session cookie, redirects to /dashboard, and grants access
        good_verify = client.post(
            "/verify?email=verify@example.com&next=/dashboard",
            data={"code": latest_code},
        )
        self.assertEqual(good_verify.status_code, 302)
        self.assertTrue(good_verify.headers["Location"].endswith("/dashboard"))
        self.assertIn("olauth_session=", good_verify.headers.get("Set-Cookie", ""))

        dash = client.get("/dashboard")
        self.assertEqual(dash.status_code, 200)
        self.assertEqual(dash.data.decode(), "verified:verify@example.com")

    def test_flask_password_reset_flow(self):
        sent_codes = []
        app = Flask(__name__)
        olauth.init(
            app,
            db=":memory:",
            redirect_to="/dashboard",
            send_verification_code=lambda email, code: sent_codes.append((email, code)),
        )

        @app.route("/dashboard")
        @olauth.login_required
        def dashboard():
            return f"dashboard:{olauth.current_user()['email']}"

        old_client = app.test_client()
        self.assertIn(b'href="/forgot-password"', old_client.get("/login").data)

        # Sign up & verify initial user so old_client holds a valid pre-reset session cookie
        old_client.post(
            "/signup",
            data={"email": "resetme@example.com", "password": "oldpassword123"},
        )
        signup_code = sent_codes.pop()[1]
        old_client.post(
            "/verify?email=resetme@example.com",
            data={"code": signup_code},
        )
        self.assertEqual(old_client.get("/dashboard").status_code, 200)

        reset_client = app.test_client()
        forgot_page = reset_client.get("/forgot-password")
        self.assertEqual(forgot_page.status_code, 200)
        self.assertIn(b"Reset your password", forgot_page.data)

        # Unknown email succeeds without sending a code (no account enumeration)
        unknown_html = reset_client.post(
            "/forgot-password",
            data={"email": "nobody@example.com"},
        )
        self.assertEqual(unknown_html.status_code, 302)
        self.assertIn("/reset-password", unknown_html.headers["Location"])
        self.assertEqual(len(sent_codes), 0)

        unknown_json = reset_client.post(
            "/forgot-password",
            json={"email": "nobody@example.com"},
            headers={"Accept": "application/json"},
        )
        self.assertEqual(unknown_json.status_code, 200)
        self.assertEqual(len(sent_codes), 0)

        # Registered email receives a 6-digit code and redirects to /reset-password
        forgot_res = reset_client.post(
            "/forgot-password?next=/dashboard",
            data={"email": "ResetMe@Example.com"},
        )
        self.assertEqual(forgot_res.status_code, 302)
        self.assertEqual(
            forgot_res.headers["Location"],
            "/reset-password?email=resetme%40example.com&next=%2Fdashboard",
        )
        self.assertEqual(len(sent_codes), 1)
        reset_code = sent_codes[0][1]

        # Wrong code fails with 400
        wrong_code = "000000" if reset_code != "000000" else "999999"
        bad_reset = reset_client.post(
            "/reset-password?email=resetme@example.com",
            data={"code": wrong_code, "password": "newstrongpassword456"},
        )
        self.assertEqual(bad_reset.status_code, 400)
        self.assertIn(b"Invalid or expired verification code", bad_reset.data)

        # Valid code updates password, sets new session, and revokes old session
        good_reset = reset_client.post(
            "/reset-password?email=resetme@example.com&next=/dashboard",
            data={"code": reset_code, "password": "newstrongpassword456"},
        )
        self.assertEqual(good_reset.status_code, 302)
        self.assertTrue(good_reset.headers["Location"].endswith("/dashboard"))
        self.assertIn("olauth_session=", good_reset.headers.get("Set-Cookie", ""))
        self.assertEqual(reset_client.get("/dashboard").status_code, 200)

        # Old session was revoked
        self.assertEqual(old_client.get("/dashboard").status_code, 302)

        # Old password fails, new password succeeds
        login_client = app.test_client()
        self.assertEqual(
            login_client.post(
                "/login",
                data={"email": "resetme@example.com", "password": "oldpassword123"},
            ).status_code,
            401,
        )
        self.assertEqual(
            login_client.post(
                "/login",
                data={"email": "resetme@example.com", "password": "newstrongpassword456"},
            ).status_code,
            302,
        )

    def test_flask_custom_templates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "login.html").write_text(
                "CUSTOM_LOGIN:{{ error }}:{{ email_value }}:{{ forgot_password_url }}",
                encoding="utf-8",
            )
            override_signup = tmp / "override_signup.html"
            override_signup.write_text(
                "OVERRIDE_SIGNUP:{{ switch_url }}",
                encoding="utf-8",
            )

            app = Flask(__name__)
            olauth.init(
                app,
                db=":memory:",
                template_dir=tmp,
                signup_template=override_signup,
            )
            client = app.test_client()

            login_html = client.get("/login").data.decode()
            self.assertIn("CUSTOM_LOGIN:::/forgot-password", login_html)

            bad_login = client.post(
                "/login",
                data={"email": "user@example.com", "password": "wrongpassword"},
            ).data.decode()
            self.assertIn("CUSTOM_LOGIN:Invalid email or password.:user@example.com:", bad_login)

            signup_html = client.get("/signup").data.decode()
            self.assertIn("OVERRIDE_SIGNUP:/login", signup_html)

            # Page not present in template_dir falls back to built-in UI
            forgot_html = client.get("/forgot-password").data.decode()
            self.assertIn("Reset your password", forgot_html)


class FastAPIEngineTests(unittest.TestCase):
    def _create_app(self, *, auto_login_on_signup=True, rate_limit=15):
        app = FastAPI()
        olauth.init(
            app,
            db=":memory:",
            redirect_to="/",
            auto_login_on_signup=auto_login_on_signup,
            rate_limit=rate_limit,
        )

        @app.get("/")
        def home(user: dict | None = Depends(olauth.current_user)):
            ctx_user = olauth.current_user()
            return {
                "dep": user["email"] if user else None,
                "ctx": ctx_user["email"] if ctx_user else None,
            }

        @app.get("/dashboard")
        def dashboard(user: dict = Depends(olauth.login_required)):
            return {"email": user["email"], "id": user["id"], "ctx": olauth.current_user()["email"]}

        return app

    def tearDown(self):
        olauth.olauth.db.close()

    def test_signup_autologin_protected_route_and_logout(self):
        app = self._create_app()
        client = TestClient(app)

        # Logged out: API request returns 401
        api_unauth = client.get("/dashboard", follow_redirects=False)
        self.assertEqual(api_unauth.status_code, 401)

        # Logged out: browser HTML request returns 303 redirect to /login?next=...
        html_unauth = client.get(
            "/dashboard?view=main",
            headers={"Accept": "text/html"},
            follow_redirects=False,
        )
        self.assertEqual(html_unauth.status_code, 303)
        self.assertIn("/login?next=%2Fdashboard%3Fview%3Dmain", html_unauth.headers["location"])

        # GET /signup returns HTML page
        get_signup = client.get("/signup")
        self.assertEqual(get_signup.status_code, 200)
        self.assertEqual(get_signup.headers.get("x-frame-options"), "DENY")

        # Short password fails validation
        bad_pw = client.post(
            "/signup",
            data={"email": "zoe@example.com", "password": "123"},
            follow_redirects=False,
        )
        self.assertEqual(bad_pw.status_code, 400)
        self.assertIn("at least 8 characters", bad_pw.text)

        # Successful signup auto-logs in and sets HttpOnly cookie
        signup_res = client.post(
            "/signup?next=/dashboard",
            data={"email": "Zoe@Example.com", "password": "strongpassword123"},
            follow_redirects=False,
        )
        self.assertEqual(signup_res.status_code, 303)
        self.assertEqual(signup_res.headers["location"], "/dashboard")
        self.assertIn("olauth_session=", signup_res.headers.get("set-cookie", ""))

        # Duplicate email fails with 400
        other_client = TestClient(app)
        dup_res = other_client.post(
            "/signup",
            data={"email": "zoe@example.com", "password": "strongpassword123"},
            follow_redirects=False,
        )
        self.assertEqual(dup_res.status_code, 400)
        self.assertIn("already exists", dup_res.text)

        # Public and protected endpoints reflect current user
        home_res = client.get("/")
        self.assertEqual(home_res.status_code, 200)
        self.assertEqual(home_res.json(), {"dep": "zoe@example.com", "ctx": "zoe@example.com"})

        dash_res = client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertEqual(dash_res.json()["email"], "zoe@example.com")
        self.assertEqual(dash_res.json()["ctx"], "zoe@example.com")

        # Logout clears session
        logout_res = client.post("/logout", follow_redirects=False)
        self.assertEqual(logout_res.status_code, 303)
        self.assertEqual(logout_res.headers["location"], "/login")

        after_logout = client.get("/dashboard", follow_redirects=False)
        self.assertEqual(after_logout.status_code, 401)

    def test_login_open_redirect_csrf_and_rate_limit(self):
        app = self._create_app(rate_limit=2)
        client = TestClient(app)

        # Create user then log out
        client.post(
            "/signup",
            data={"email": "max@example.com", "password": "password1234"},
            follow_redirects=False,
        )
        client.get("/logout", follow_redirects=False)

        # Cross-site Sec-Fetch-Site blocked
        csrf_res = client.post(
            "/login",
            data={"email": "max@example.com", "password": "password1234"},
            headers={"Sec-Fetch-Site": "cross-site"},
            follow_redirects=False,
        )
        self.assertEqual(csrf_res.status_code, 403)

        # 2 failed login attempts -> 401, 3rd -> 429
        for _ in range(2):
            bad = client.post(
                "/login",
                data={"email": "max@example.com", "password": "wrong"},
                follow_redirects=False,
            )
            self.assertEqual(bad.status_code, 401)

        limited = client.post(
            "/login",
            data={"email": "max@example.com", "password": "password1234"},
            follow_redirects=False,
        )
        self.assertEqual(limited.status_code, 429)

        # Verify open redirect blocked with a fresh app/rate limit
        app2 = self._create_app(rate_limit=15)
        c2 = TestClient(app2)
        c2.post(
            "/signup",
            data={"email": "max@example.com", "password": "password1234"},
            follow_redirects=False,
        )
        c2.get("/logout", follow_redirects=False)

        login_evil = c2.post(
            "/login?next=//evil.com",
            data={"email": "max@example.com", "password": "password1234"},
            follow_redirects=False,
        )
        self.assertEqual(login_evil.status_code, 303)
        self.assertEqual(login_evil.headers["location"], "/")

        c2.get("/logout", follow_redirects=False)
        login_good = c2.post(
            "/login?next=/dashboard",
            data={"email": "max@example.com", "password": "password1234"},
            follow_redirects=False,
        )
        self.assertEqual(login_good.status_code, 303)
        self.assertEqual(login_good.headers["location"], "/dashboard")

    def test_fastapi_json_auth_already_logged_in_and_async_decorator(self):
        app = FastAPI()
        olauth.init(app, db=":memory:", redirect_to="/")

        @app.get("/async-secret")
        @olauth.login_required
        async def async_secret():
            return {"email": olauth.current_user()["email"]}

        client = TestClient(app)
        self.assertEqual(client.get("/async-secret").status_code, 401)

        signup_json = client.post(
            "/signup",
            json={"email": "async@example.com", "password": "strongpassword123"},
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
        self.assertEqual(signup_json.status_code, 201)
        self.assertEqual(signup_json.json()["user"]["email"], "async@example.com")

        # Already authenticated GET /login and GET /signup redirect
        self.assertEqual(client.get("/login", follow_redirects=False).status_code, 303)
        self.assertEqual(client.get("/signup", follow_redirects=False).status_code, 303)

        secret_res = client.get("/async-secret")
        self.assertEqual(secret_res.status_code, 200)
        self.assertEqual(secret_res.json(), {"email": "async@example.com"})

        logout_json = client.post(
            "/logout",
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
        self.assertEqual(logout_json.status_code, 200)
        self.assertEqual(logout_json.json(), {"message": "Logged out"})
        self.assertEqual(client.get("/async-secret").status_code, 401)

    def test_fastapi_email_verification_code_flow(self):
        sent_codes = []
        app = FastAPI()
        olauth.init(
            app,
            db=":memory:",
            redirect_to="/",
            send_verification_code=lambda email, code: sent_codes.append((email, code)),
        )

        @app.get("/dashboard")
        def dashboard(user: dict = Depends(olauth.login_required)):
            return {"verified": user["email"]}

        client = TestClient(app)

        # Signup redirects to /verify without session cookie
        signup_res = client.post(
            "/signup?next=/dashboard",
            data={"email": "FastVerify@Example.com", "password": "strongpassword123"},
            follow_redirects=False,
        )
        self.assertEqual(signup_res.status_code, 303)
        self.assertEqual(
            signup_res.headers["location"],
            "/verify?email=fastverify%40example.com&next=%2Fdashboard",
        )
        self.assertNotIn("olauth_session=", signup_res.headers.get("set-cookie", ""))
        self.assertEqual(len(sent_codes), 1)

        # Unverified login returns 303 to /verify (or 403 JSON)
        login_html = client.post(
            "/login",
            data={"email": "fastverify@example.com", "password": "strongpassword123"},
            follow_redirects=False,
        )
        self.assertEqual(login_html.status_code, 303)
        self.assertIn("/verify?email=fastverify%40example.com", login_html.headers["location"])

        login_json = client.post(
            "/login",
            json={"email": "fastverify@example.com", "password": "strongpassword123"},
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
        self.assertEqual(login_json.status_code, 403)
        latest_code = sent_codes[-1][1]

        # Wrong code returns 400
        wrong_code = "000000" if latest_code != "000000" else "999999"
        bad_verify = client.post(
            "/verify?email=fastverify@example.com&next=/dashboard",
            data={"code": wrong_code},
            follow_redirects=False,
        )
        self.assertEqual(bad_verify.status_code, 400)
        self.assertIn("Invalid or expired verification code", bad_verify.text)

        # Valid code verifies, sets cookie, redirects to /dashboard, and unlocks route
        good_verify = client.post(
            "/verify?email=fastverify@example.com&next=/dashboard",
            data={"code": latest_code},
            follow_redirects=False,
        )
        self.assertEqual(good_verify.status_code, 303)
        self.assertEqual(good_verify.headers["location"], "/dashboard")
        self.assertIn("olauth_session=", good_verify.headers.get("set-cookie", ""))

        dash = client.get("/dashboard")
        self.assertEqual(dash.status_code, 200)
        self.assertEqual(dash.json(), {"verified": "fastverify@example.com"})

    def test_fastapi_password_reset_flow(self):
        sent_codes = []
        app = FastAPI()
        olauth.init(
            app,
            db=":memory:",
            redirect_to="/dashboard",
            send_verification_code=lambda email, code: sent_codes.append((email, code)),
        )

        @app.get("/dashboard")
        def dashboard(user: dict = Depends(olauth.login_required)):
            return {"email": user["email"]}

        old_client = TestClient(app)
        self.assertIn('href="/forgot-password"', old_client.get("/login").text)

        # Create & verify user so old_client has an active session
        old_client.post(
            "/signup",
            data={"email": "fastreset@example.com", "password": "oldpassword123"},
            follow_redirects=False,
        )
        signup_code = sent_codes.pop()[1]
        old_client.post(
            "/verify?email=fastreset@example.com",
            data={"code": signup_code},
            follow_redirects=False,
        )
        self.assertEqual(old_client.get("/dashboard").status_code, 200)

        reset_client = TestClient(app)
        self.assertEqual(reset_client.get("/forgot-password").status_code, 200)

        # HTML forgot-password redirect (303) and JSON response (200)
        forgot_html = reset_client.post(
            "/forgot-password?next=/dashboard",
            data={"email": "fastreset@example.com"},
            follow_redirects=False,
        )
        self.assertEqual(forgot_html.status_code, 303)
        self.assertEqual(
            forgot_html.headers["location"],
            "/reset-password?email=fastreset%40example.com&next=%2Fdashboard",
        )
        self.assertEqual(len(sent_codes), 1)

        # Unknown email does not emit a code
        unknown_json = reset_client.post(
            "/forgot-password",
            json={"email": "missing@example.com"},
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
        self.assertEqual(unknown_json.status_code, 200)
        self.assertEqual(len(sent_codes), 1)

        reset_code = sent_codes[0][1]

        # JSON reset-password with valid code sets session cookie and revokes old session
        good_json_reset = reset_client.post(
            "/reset-password?next=/dashboard",
            json={
                "email": "fastreset@example.com",
                "code": reset_code,
                "password": "newstrongpassword456",
            },
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
        self.assertEqual(good_json_reset.status_code, 200)
        self.assertEqual(good_json_reset.json()["user"]["email"], "fastreset@example.com")
        self.assertEqual(good_json_reset.json()["redirect_to"], "/dashboard")
        self.assertIn("olauth_session=", good_json_reset.headers.get("set-cookie", ""))
        self.assertEqual(reset_client.get("/dashboard").status_code, 200)

        # Old session was revoked
        self.assertEqual(old_client.get("/dashboard", follow_redirects=False).status_code, 401)

        # Old password rejected, new password accepted
        login_client = TestClient(app)
        self.assertEqual(
            login_client.post(
                "/login",
                data={"email": "fastreset@example.com", "password": "oldpassword123"},
                follow_redirects=False,
            ).status_code,
            401,
        )
        self.assertEqual(
            login_client.post(
                "/login",
                data={"email": "fastreset@example.com", "password": "newstrongpassword456"},
                follow_redirects=False,
            ).status_code,
            303,
        )

    def test_fastapi_custom_templates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "login.html").write_text("SHOULD_BE_OVERRIDDEN", encoding="utf-8")
            (tmp / "signup.html").write_text(
                "FAST_SIGNUP:{{ error }}:{{ switch_url }}",
                encoding="utf-8",
            )
            override_login = tmp / "custom_login.html"
            override_login.write_text(
                "FAST_LOGIN_OVERRIDE:{{ forgot_password_url }}",
                encoding="utf-8",
            )

            app = FastAPI()
            olauth.init(
                app,
                db=":memory:",
                template_dir=tmp,
                login_template=override_login,
            )
            client = TestClient(app)

            login_text = client.get("/login").text
            self.assertEqual(login_text, "FAST_LOGIN_OVERRIDE:/forgot-password")

            signup_text = client.get("/signup").text
            self.assertEqual(signup_text, "FAST_SIGNUP::/login")

            # Built-in fallback for pages absent from template_dir
            reset_text = client.get("/reset-password").text
            self.assertIn("Set a new password", reset_text)


if __name__ == "__main__":
    unittest.main()
