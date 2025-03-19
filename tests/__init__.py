import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Rest of your imports
from app.database.db import init_db, URLThreat