import html

from flask import Flask
import olauth

app = Flask(__name__)
olauth.init(app)


@app.route("/")
def home():
    user = olauth.current_user()
    if user:
        safe_email = html.escape(user["email"])
        return (
            f"<h1>Welcome back, {safe_email}</h1>"
            '<p><a href="/dashboard">Go to Dashboard</a> | <a href="/logout">Log out</a></p>'
        )
    return (
        "<h1>Welcome to the App</h1>"
        '<p><a href="/signup">Sign up</a> | <a href="/login">Log in</a> | '
        '<a href="/dashboard">Dashboard (protected)</a></p>'
    )


@app.route("/dashboard")
@olauth.login_required
def dashboard():
    user = olauth.current_user()
    safe_email = html.escape(user["email"])
    return (
        f"<h1>Dashboard</h1>"
        f"<p>Signed in as <strong>{safe_email}</strong> (user #{user['id']})</p>"
        '<p><a href="/">Home</a> | <a href="/logout">Log out</a></p>'
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
