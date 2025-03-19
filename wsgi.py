from app import create_app
from config import Configuration

app = create_app(Configuration)

if __name__ == "__main__":
    app.run()
