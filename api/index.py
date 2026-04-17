import os
import sys

# Append the project root to the Python path so Vercel can find your internal modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mangum import Mangum
from main import app

# This handler wraps your beautiful FastAPI application for AWS Lambda/Vercel execution
handler = Mangum(app)
