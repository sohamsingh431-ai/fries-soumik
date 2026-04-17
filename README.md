# ScamShield Engine

ScamShield is a production-grade cybersecurity analysis engine meant for detecting employment scam signals. It includes a modular detection engine (`cyber.py`) and a fully built API interface (`main.py`).

## Setup Instructions (For a fresh laptop)

To run this application on a new machine, follow these steps:

### 1. Install Python
Ensure that Python 3.8+ (preferably 3.10+) is installed on your system.

### 2. Clone the repository
```bash
git clone https://github.com/sohamsingh431-ai/fries-soumik.git
cd fries-soumik
```
*(If you have named the local folder something else like `cyber`, navigate into that folder directory instead)*

### 3. Create a Virtual Environment (Recommended)
You should create an isolated virtual environment to prevent package conflicts:
```bash
# On Windows:
python -m venv venv
venv\Scripts\activate

# On Mac/Linux:
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
Install all required libraries specified in `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 5. Running the Application

**Option A: Run the API Server**
The project runs via FastAPI. To run the API Server using Uvicorn:
```bash
python main.py
```
Or you can use uvicorn directly:
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Once it's running, you can access the interactive API docs at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

**Option B: Run the Command Line Engine (Testing Mode)**
To just run the heuristic engine testing script directly in your terminal:
```bash
python cyber.py
```
