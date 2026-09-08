"""Entrypoint: `python app.py` for dev, `gunicorn app:app` in production."""
from vigia import create_app
from vigia.config import load_settings

app = create_app()

if __name__ == "__main__":
    settings = load_settings()
    app.run(host="127.0.0.1", port=settings.port, debug=settings.debug)
