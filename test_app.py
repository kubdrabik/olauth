from flask import Flask
import olauth

app = Flask(__name__)
olauth.init(app)

@app.route("/")
def home():
    return '<h1>Welcome to the App</h1><p>Go to <a href="/signup">/signup</a> to try OL-Auth!</p>'

if __name__ == "__main__":
    app.run(debug=True, port=5000)