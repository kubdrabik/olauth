from flask import Blueprint, request, render_template_string, redirect, make_response
from .crypto import hash_password, verify_password

# Monolithic HTML framework view template leveraging native Jinja2 compilation context
BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        :root {
            --bg: #ffffff; --text: #111111; --border: #e2e8f0; --input-bg: #ffffff;
            --btn-bg: #000000; --btn-text: #ffffff; --btn-hover: #1a1a1a; --focus-ring: #000000;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #0b0f19; --text: #f9fafb; --border: #374151; --input-bg: #111827;
                --btn-bg: #ffffff; --btn-text: #000000; --btn-hover: #e5e7eb; --focus-ring: #ffffff;
            }
        }
        body { background-color: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; padding: 24px; box-sizing: border-box; }
        .card { width: 100%; max-width: 400px; padding: 40px 32px; border: 1px solid var(--border); border-radius: 12px; box-sizing: border-box; }
        h1 { font-size: 24px; font-weight: 700; margin: 0 0 8px 0; letter-spacing: -0.5px; }
        .error-msg { color: #ef4444; font-size: 14px; margin-bottom: 16px; font-weight: 500; }
        .field { margin-bottom: 20px; }
        label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; opacity: 0.85; }
        input { width: 100%; padding: 12px; font-size: 16px; font-family: inherit; border: 1px solid var(--border); border-radius: 6px; background-color: var(--input-bg); color: var(--text); box-sizing: border-box; }
        input:focus { outline: none; border-color: var(--focus-ring); box-shadow: 0 0 0 2px var(--bg), 0 0 0 4px var(--focus-ring); }
        button { width: 100%; padding: 12px; font-size: 16px; font-weight: 600; font-family: inherit; border-radius: 6px; border: none; background-color: var(--btn-bg); color: var(--btn-text); cursor: pointer; }
        button:hover { background-color: var(--btn-hover); }
        .switch-text { margin-top: 20px; font-size: 14px; text-align: center; opacity: 0.7; }
        .switch-text a { color: var(--text); font-weight: 600; text-decoration: underline; }
    </style>
</head>
<body>
    <div class="card">
        <h1>{{ heading }}</h1>
        
        {% if error %}
            <div class="error-msg">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="field">
                <label for="email">Email address</label>
                <input type="email" id="email" name="email" required placeholder="you@example.com">
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="••••••••">
            </div>
            <button type="submit">{{ button_text }}</button>
            <div class="switch-text">
                {{ switch_prompt }} <a href="{{ switch_url }}">{{ switch_action }}</a>
            </div>
        </form>
    </div>
</body>
</html>
"""

def inject_flask(app, db):
    """Dynamically registers authentication endpoints and view logic onto the host Flask application."""
    
    olauth_bp = Blueprint("olauth", __name__)

    # --- SIGN UP FLOW ---
    @olauth_bp.route("/signup", methods=["GET", "POST"])
    def signup():
        error = ""
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            
            hashed = hash_password(password)
            success = db.create_user(email, hashed)
            
            if success:
                return redirect("/login")
            else:
                error = "An account with that email already exists."

        # Bind template layout to the sign-up context properties
        return render_template_string(
            BASE_HTML,
            title="Sign up",
            heading="Create an account",
            button_text="Sign up",
            error=error,
            switch_prompt="Already have an account?",
            switch_url="/login",
            switch_action="Log in"
        )

    # --- LOG IN FLOW ---
    @olauth_bp.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            
            user = db.get_user_by_email(email)
            
            if user and verify_password(password, user["password_hash"]):
                return f"Success! Logged in as: {user['email']}"
            else:
                error = "Invalid email or password."

        # Bind template layout to the log-in context properties
        return render_template_string(
            BASE_HTML,
            title="Log in",
            heading="Log in to your account",
            button_text="Log in",
            error=error,
            switch_prompt="Don't have an account?",
            switch_url="/signup",
            switch_action="Sign up"
        )

    # Mount the fully configured authorization routing tier to the core runtime application
    app.register_blueprint(olauth_bp)
