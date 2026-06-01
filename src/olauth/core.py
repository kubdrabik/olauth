import sys
from .database import DatabaseManager

class OLAuth:
    """Core orchestrator responsible for framework detection and routing injection."""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.framework = None

    def init(self, app, db=None):
        """Discovers the host framework at runtime and mounts the corresponding auth engine."""
        self.db.initialize_db(db)
        
        # Stringify the module path to safely identify the framework without hard imports
        app_type = f"{type(app).__module__}.{type(app).__name__}"
        
        if "flask" in app_type:
            self.framework = "flask"
            # Lazy-load engine to avoid importing unused framework dependencies
            from .engine_flask import inject_flask
            inject_flask(app, self.db) 
            
        elif "fastapi" in app_type or "starlette" in app_type:
            self.framework = "fastapi"
            from .engine_fastapi import inject_fastapi
            inject_fastapi(app, self.db)
            
        else:
            raise ValueError(f"[OL-Auth] Unsupported framework: {app_type}")

# Export a single global instance for the one-liner initialization pattern
olauth = OLAuth()