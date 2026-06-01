# OL-Auth (v0.1.0a1)

OL-Auth is a lightweight, zero-configuration authentication engine designed to eliminate bootstrap friction in Python web applications. By initializing the library with a single line of code, it provisions a local data store, manages password encryption, and serves responsive, system-adaptive **Log in** and **Sign up** interfaces directly into your application.

---

## 🎯 Ideal for Hackathons & Rapid Prototyping

When building prototypes or competing in hackathons, setting up authentication flows (tables, encryption, form handling, and UI styling) repeatedly eats up valuable hours. OL-Auth handles this scaffolding instantly so you can focus entirely on building your core features. 

### Current Status: Flask Only
> ⚠️ **Note:** OL-Auth is currently in an early **Alpha** development phase. It presently **only supports the Flask framework** and utilizes an internal, automated SQLite database. 

---

## 📦 Installation (Local Development)

Since the package is in alpha and not yet published to PyPI, install it in editable mode within your virtual environment:

```bash
pip install -e .
```
## 💻 Usage Example

```python
from flask import Flask
import olauth

app = Flask(__name__)

# Single-line initialization: automatically builds tables and mounts routes
olauth.init(app)

@app.route("/")
def home():
    return 'Welcome! Visit <a href="/signup">/signup</a> to create an account.'

if __name__ == "__main__":
    app.run(debug=True)
```

Once initialized, the library automatically registers and serves the following endpoints:
* `/signup` — Renders the registration form and handles user creation.
* `/login` — Renders the authentication form and verifies credentials.

## 🛠️ Upcoming Roadmap

We are actively developing the core foundation to bring this library to a stable Beta release. The immediate roadmap focuses on the following four milestones:

1. **Session Validation & State Handling:** Integrating secure token generation and browser cookie management to keep users authenticated across page requests.
2. **FastAPI Engine Support:** Replicating the routing injection logic via `APIRouter` to support FastAPI applications.
3. **Targeted Database Connectors:** Expanding the database driver layer to allow seamless scaling by supporting connection strings for:
   * **PostgreSQL** (Enterprise relational storage)
   * **MongoDB** (NoSQL document storage)
4. **Performance Optimization:** Tuning connection pooling and cryptographic work-factors to resolve initial execution slowness.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.