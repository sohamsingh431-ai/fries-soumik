# ScamShield CyberScam Engine

This is the full-power, production-grade cybersecurity analysis engine for ScamShield. It implements the complete architecture specified in the Cyber Layer design, featuring 13 distinct checks across 6 intelligent modules.

## Prerequisites

- Python 3.10+
- pip (Python package manager)

## Setup Instructions for a Clean Machine

1. **Clone/Download the Repository**
   Ensure you have the `cyberscam` folder on your local machine.
   ```bash
   cd path/to/cyberscam
   ```

2. **Create a Virtual Environment (Optional but Recommended)**
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**
   Install all required packages listed in the `requirements.txt` file.
   ```bash
   pip install -r requirements.txt
   ```

4. **Download GeoLite2 Database (Highly Recommended)**
   For the IP Geolocation checks to work, you need the MaxMind GeoLite2 City database.
   - The engine looks for a file named `GeoLite2-City.mmdb` in the same directory.
   - If it is missing, the engine will gracefully degrade and try to use fallback APIs, but local DB is faster.
   - You can sign up for a free MaxMind account to download it, or use the fallback.

## Running the Server

Start the FastAPI server using Uvicorn:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

*Note: On Windows, if you encounter encoding errors in the terminal output from uvicorn or tests, run Python with the UTF-8 flag:*
```bash
python -X utf8 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

## How to Use the API

Once the server is running, the API is accessible locally.

1. **Interactive API Documentation (Swagger UI)**
   Open your browser and navigate to:
   http://localhost:8000/docs
   
   Here you can interactively test the `/api/check` endpoint by providing test data.

2. **Endpoints**
   - `POST /api/check`: Submit job posting details for full cyber analysis.
   - `GET /api/stats`: View aggregated statistics of the checks performed.
   - `GET /api/history`: View recent check history.
   - `GET /api/health`: Check if the engine is running.

## Running the Test Suite

A comprehensive test suite is provided to verify the engine's capability against various scenarios (obvious scam, subtle scam, legitimate, etc.).

```bash
python -X utf8 test_full.py
```
