# AI Threat Assessor

A Flask-based web application designed to evaluate AI model conversations for potential safety and ethical risks, including dangerous content generation, gender bias, and bypassing regulations. It uses a separate AI model (configurable, e.g., Google Gemini Pro/Flash) to perform the evaluation based on specific criteria.

## Features

*   **Web Interface:** Simple UI built with Flask and Bootstrap for submitting conversations and viewing results.
*   **Raw Text Input:** Accepts raw conversation history text.
*   **Conversation Parsing:** Parses raw text into structured user/assistant turns based on common prefixes (User:, Assistant:, Question:, Answer:, etc.). Assumes the first block is 'user' if no prefix found.
*   **Source LLM Tracking:** Records the name of the AI model that generated the original conversation.
*   **AI-Powered Evaluation:** Integrates with the Google Generative AI API (Gemini models) to evaluate submitted conversations.
*   **Two-Stage Evaluation:**
    1.  **Dangerous Content Check:** A focused check for instructions related to dangerous items/substances.
    2.  **Multi-Criteria Check:** If the conversation passes the dangerous content check, it's evaluated for gender bias and bypassing EU laws using a more complex prompt.
*   **Risk Flagging:** Assigns an overall flag (Red, Orange, Green, White) based on the evaluation results' severity.
*   **Database Storage:** Persists evaluation submissions, results (raw and parsed), and metadata to a MongoDB database.
*   **History View:** Displays a table of the last 50 evaluations.
*   **Visualizations:** Includes bar and pie charts (using Chart.js) summarizing the distribution of detected issues and overall risk flags across the stored history.
*   **Configuration:** Key settings (API keys, DB connection, evaluation model) managed via a `.env` file.

## Technology Stack

*   **Backend:** Python 3.9+, Flask
*   **Database:** MongoDB (using `pymongo` driver)
*   **AI Evaluation:** Google Generative AI API (`google-generativeai` library)
*   **Frontend:** HTML, CSS (Bootstrap 5), JavaScript (Chart.js)
*   **Environment:** `python-dotenv` for managing environment variables
*   **Process Management (Optional):** PM2 (demonstrated during debugging)

## Prerequisites

*   **Python:** Version 3.9 or higher recommended.
*   **pip:** Python package installer (usually included with Python).
*   **MongoDB:** A running MongoDB instance (local, Docker, or cloud service like MongoDB Atlas). Note down the connection details (IP/Hostname, Port, Username, Password, Auth Database).
*   **Google API Key:** An API key from Google AI Studio or a Google Cloud project with the Generative Language API enabled.
*   **Git:** (Optional) For cloning the repository.

## Installation & Setup

1.  **Clone the Repository (or Download Files):**
    ```bash
    git clone https://github.com/nani-1205/ai_threat_assessor.git
    cd ai_threat_assessor
    ```
    (If you downloaded a zip, extract it and navigate into the `ai_threat_assessor` directory).

2.  **Create and Activate Virtual Environment:**
    ```bash
    # Create venv
    python -m venv venv

    # Activate (Linux/macOS)
    source venv/bin/activate

    # Activate (Windows Command Prompt)
    .\venv\Scripts\activate

    # Activate (Windows PowerShell)
    .\venv\Scripts\Activate.ps1
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

1.  **Create `.env` File:** Create a file named `.env` in the project's root directory (`ai_threat_assessor/`).
2.  **Populate `.env`:** Add the following variables, replacing the placeholder values with your actual credentials and preferences:

    ```dotenv
    # .env file

    # --- Google AI API ---
    GOOGLE_API_KEY=YOUR_GOOGLE_AI_STUDIO_API_KEY_HERE

    # --- Evaluation Model ---
    # Strongly recommended: gemini-1.5-pro-latest for better nuance detection
    # Alternative: gemini-1.5-flash-latest (faster, potentially less accurate)
    EVALUATION_MODEL_NAME=gemini-1.5-pro-latest

    # --- MongoDB Connection ---
    MONGO_IP=YOUR_MONGODB_IP_OR_HOSTNAME # e.g., localhost or cluster URL
    MONGO_PORT=27017 # Default MongoDB port
    MONGO_USERNAME=YOUR_MONGO_USERNAME # Leave blank if no auth
    MONGO_PASSWORD=YOUR_MONGO_PASSWORD # Leave blank if no auth
    MONGO_AUTH_DB=admin # Database to authenticate against (often 'admin' or the specific DB name)
    MONGO_DB_NAME=ai_threat_assessments # Database to store assessments in

    # --- Flask Security ---
    # Generate a strong, random secret key (e.g., using python -c 'import secrets; print(secrets.token_hex(16))')
    FLASK_SECRET_KEY=YOUR_STRONG_RANDOM_FLASK_SECRET_KEY
    ```

3.  **Security:** **Never** commit your `.env` file to version control (Git). Ensure the `.gitignore` file includes `.env`.

## Running the Application

1.  **Ensure MongoDB is Running:** Start your local MongoDB server or ensure your cloud instance is accessible.
2.  **Activate Virtual Environment:** (If not already active) `source venv/bin/activate` or equivalent.
3.  **Run with Flask Development Server:**
    ```bash
    python app.py
    ```
    The application will typically be available at `http://127.0.0.1:5000` or `http://0.0.0.0:5000`. Check the terminal output. Note that `debug=False` is set in the code for production-like behavior.

4.  **Running with PM2 (for Background Process / Production-like):**
    *   Install PM2 globally if you haven't: `npm install pm2 -g`
    *   Start the application:
        ```bash
        pm2 start app.py --name ai-assessor --watch --interpreter python3
        ```
        (`--watch` automatically restarts on file changes, remove for stable production).
    *   **View Logs:**
        *   Combined logs: `pm2 logs ai-assessor`
        *   **Error/Application logs:** `pm2 logs ai-assessor --err` (This is where `logging` messages go)
        *   Output logs: `pm2 logs ai-assessor --out`
    *   **Stop:** `pm2 stop ai-assessor`
    *   **Restart:** `pm2 restart ai-assessor`
    *   **Delete:** `pm2 delete ai-assessor` (Needed sometimes to fully reload environment variables from `.env`).

## Usage Guide

1.  **Access the UI:** Open your web browser and navigate to the URL where the application is running (e.g., `http://<your-server-ip>:5000`).
2.  **Enter Source LLM:** Type the name or identifier of the AI model that produced the conversation you want to evaluate.
3.  **Paste Conversation:** Copy the raw text of the conversation history into the "Conversation History (Raw Text)" text area.
    *   **Format:** Ensure distinct turns are separated by newlines. Indicate roles using prefixes like `User:`, `Assistant:`, `Question:`, `Answer:`, etc., at the beginning of the relevant lines. The parser assumes the first block of text is the 'user' role if no prefix is found there. **Crucially, ensure there is text marked with an assistant prefix** for the evaluation to run.
4.  **Evaluate:** Click the "Evaluate Conversation" button.
5.  **View Results:** The page will refresh.
    *   **Flashed Messages:** Look for success, warning, or error messages at the top.
    *   **Last Evaluation Result:** This section shows the submitted text, the parsed conversation (if successful), and the detailed AI evaluation outcome (flags, explanation).
    *   **History Table:** The table updates with the latest evaluation entry.
    *   **Charts:** The charts update to reflect the new statistics.

