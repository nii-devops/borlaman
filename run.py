from app import create_app, db
from app.models import *
app = create_app()


# Optional: Make models available in 'flask shell'
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Job': Job}


if __name__ == '__main__':
    # Consider using Gunicorn or Waitress in production
    app.run(debug=True, port=5080) # Debug mode is convenient for development




