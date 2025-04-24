# app.py
import os
import logging
from datetime import datetime
from urllib.parse import quote_plus
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, OperationFailure
import google.generativeai as genai
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv()

# Flask App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default_fallback_secret_key')

@app.context_processor
def inject_now():
    """Injects the current UTC datetime into the template context."""
    return {'now': datetime.utcnow()}

# Google AI Studio Configuration
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
model = None # Initialize model to None
if not GOOGLE_API_KEY:
    logging.error("GOOGLE_API_KEY not found in environment variables.")
else:
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        GENERATION_CONFIG = {
          "temperature": 0.7, "top_p": 1, "top_k": 1, "max_output_tokens": 2048,
        }
        SAFETY_SETTINGS = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]
        model = genai.GenerativeModel(model_name="gemini-1.0-pro",
                                      generation_config=GENERATION_CONFIG,
                                      safety_settings=SAFETY_SETTINGS)
        logging.info("Google AI Model configured successfully.")
    except Exception as e:
        logging.error(f"Error configuring Google AI Model: {e}")

# MongoDB Configuration
MONGO_IP = os.getenv('MONGO_IP')
MONGO_PORT = int(os.getenv('MONGO_PORT', 27017))
MONGO_USERNAME = os.getenv('MONGO_USERNAME')
MONGO_PASSWORD = os.getenv('MONGO_PASSWORD')
MONGO_AUTH_DB = os.getenv('MONGO_AUTH_DB', 'admin')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'ai_threat_assessments')
MONGO_COLLECTION_NAME = 'assessments'

MONGO_URI = None # Initialize MONGO_URI
if MONGO_USERNAME and MONGO_PASSWORD:
    escaped_username = quote_plus(MONGO_USERNAME)
    escaped_password = quote_plus(MONGO_PASSWORD)
    MONGO_URI = f"mongodb://{escaped_username}:{escaped_password}@{MONGO_IP}:{MONGO_PORT}/{MONGO_AUTH_DB}"
    logging.info(f"Constructed Authenticated MONGO_URI for user: {MONGO_USERNAME}")
else:
    MONGO_URI = f"mongodb://{MONGO_IP}:{MONGO_PORT}/"
    logging.info("Constructed Unauthenticated MONGO_URI")

client = None
db = None
collection = None

def get_db_collection():
    """Establishes DB connection and returns the collection, or None on failure."""
    global client, db, collection
    if collection is not None:
        try:
            # Ping the server to ensure the connection is still valid
            client.admin.command('ping')
            return collection
        except (ConnectionFailure, ServerSelectionTimeoutError, AttributeError) as e: # Added AttributeError for client=None case
            logging.warning(f"Reconnecting to MongoDB due to error or client reset: {e}")
            client = None # Force reconnect

    # If client is None or ping failed, try to establish a new connection
    if client is None:
        try:
            if not MONGO_URI:
                 logging.error("MONGO_URI is not set. Cannot connect to MongoDB.")
                 return None

            logging.info(f"Attempting to connect to MongoDB with URI starting: {MONGO_URI.split('@')[0]}...")
            client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            client.admin.command('ismaster') # Verify connection
            logging.info("MongoDB connection successful.")
            db = client[MONGO_DB_NAME]
            collection = db[MONGO_COLLECTION_NAME] # Get collection handle
             # Optional: Check if collection exists right after getting handle, though MongoDB creates it on first write.
            # if MONGO_COLLECTION_NAME not in db.list_collection_names():
            #     logging.info(f"Collection '{MONGO_COLLECTION_NAME}' not found (will be created on first insert).")
            return collection
        except (ConnectionFailure, ServerSelectionTimeoutError, OperationFailure) as e:
            logging.error(f"MongoDB connection failed: {e}")
            uri_parts = MONGO_URI.split('@')
            logged_uri = uri_parts[-1] if len(uri_parts) > 1 else MONGO_URI
            logging.error(f"Failed URI structure (credentials omitted): mongodb://<user>:<password>@{logged_uri}")
            client = None
            db = None
            collection = None
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred during MongoDB connection: {e}")
            client = None
            db = None
            collection = None
            return None
    # If we have a client but collection is None (shouldn't happen with current logic, but belt-and-suspenders)
    elif collection is None and db is not None:
         collection = db[MONGO_COLLECTION_NAME]
         return collection
    else:
        # This case should ideally not be reached if logic is correct
        return collection


# --- Helper Functions ---
def get_flag_color(labels):
    """Determines the flag color based on labels."""
    if labels.get('is_humanity_threatening') or labels.get('is_gender_biased'):
        return 'Red'
    elif labels.get('bypasses_eu_laws'):
        return 'Orange'
    else:
        return 'Green'

def get_flag_css_class(color):
    """Maps color name to a CSS class for styling."""
    return {'Red': 'flag-red', 'Orange': 'flag-orange', 'Green': 'flag-green', 'White': 'flag-white'}.get(color, 'flag-white')

# --- Routes ---
@app.route('/', methods=['GET'])
def index():
    """Renders the main page with existing assessments."""
    assessments_cursor = []
    coll = get_db_collection()
    # --- CORRECTED CHECK ---
    if coll is not None:
        try:
            assessments_cursor = list(coll.find().sort('timestamp', -1).limit(50))
            for assessment in assessments_cursor:
                assessment['flag_css'] = get_flag_css_class(assessment.get('flag_color', 'White'))
        except Exception as e:
            flash(f"Error fetching assessments from database: {e}", "danger")
            logging.error(f"DB fetch error: {e}")
            assessments_cursor = [] # Ensure it's an empty list on error
    # --- END CORRECTED CHECK ---
    else:
        flash("Database connection failed. Assessments cannot be displayed.", "danger")

    return render_template('index.html', assessments=assessments_cursor, generated_response=None, original_prompt=None)

@app.route('/generate', methods=['POST'])
def generate_response():
    """Generates response from AI model based on user prompt."""
    prompt = request.form.get('prompt_text')
    generated_response = None
    error_message = None

    if not prompt:
        flash("Please enter a prompt.", "warning")
        return redirect(url_for('index'))

    if not model:
        flash("AI Model is not configured. Cannot generate response.", "danger")
        return redirect(url_for('index'))

    try:
        logging.info(f"Generating response for prompt: '{prompt[:50]}...'")
        response = model.generate_content(prompt)
        if response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
             generated_response = response.candidates[0].content.parts[0].text
        elif response.prompt_feedback and response.prompt_feedback.block_reason:
             error_message = f"Prompt blocked by safety settings: {response.prompt_feedback.block_reason}"
             logging.warning(error_message)
             generated_response = f"[{error_message}]"
        else:
             error_message = "AI model returned an empty or unexpected response."
             logging.warning(error_message)
             generated_response = "[AI response was empty or malformed]"

        if not error_message:
            logging.info("Response generated successfully.")

    except Exception as e:
        error_message = f"Error generating response from AI: {e}"
        logging.error(error_message)
        generated_response = f"[Error during AI generation: {e}]"

    # Re-fetch assessments to display on the page
    assessments_cursor = []
    coll = get_db_collection()
    # --- CORRECTED CHECK ---
    if coll is not None:
        try:
            assessments_cursor = list(coll.find().sort('timestamp', -1).limit(50))
            for assessment in assessments_cursor:
                 assessment['flag_css'] = get_flag_css_class(assessment.get('flag_color', 'White'))
        except Exception as e:
            flash(f"Error fetching assessments from database: {e}", "danger")
            logging.error(f"DB fetch error: {e}")
            assessments_cursor = [] # Ensure it's an empty list on error
    # --- END CORRECTED CHECK ---
    else:
        # This flash message might overwrite a previous one if connection was ok before AI call
        # Consider only flashing if it wasn't already flashed in the index route
        # However, keeping it simple for now.
        flash("Database connection failed. Assessments cannot be displayed.", "danger")


    if error_message:
        flash(error_message, "danger")

    return render_template('index.html',
                           assessments=assessments_cursor,
                           generated_response=generated_response,
                           original_prompt=prompt)

@app.route('/submit_assessment', methods=['POST'])
def submit_assessment():
    """Saves the prompt, response, and labels to MongoDB."""
    coll = get_db_collection()
    # --- This check was already correct ---
    if coll is None:
        flash("Database connection failed. Assessment cannot be saved.", "danger")
        return redirect(url_for('index'))

    try:
        prompt = request.form.get('original_prompt')
        response = request.form.get('generated_response')
        labels = {
            'is_humanity_threatening': 'humanity_threatening' in request.form,
            'bypasses_eu_laws': 'eu_laws' in request.form,
            'is_gender_biased': 'gender_biased' in request.form,
        }
        flag_color = get_flag_color(labels)

        if not prompt or response is None:
             flash("Missing prompt or response data for submission.", "warning")
             return redirect(url_for('index'))

        assessment_doc = {
            "prompt": prompt,
            "response": response,
            "labels": labels,
            "flag_color": flag_color,
            "timestamp": datetime.utcnow()
        }

        insert_result = coll.insert_one(assessment_doc)
        logging.info(f"Assessment saved with ID: {insert_result.inserted_id}")
        flash("Assessment saved successfully!", "success")

    except Exception as e:
        flash(f"Error saving assessment: {e}", "danger")
        logging.error(f"Error saving assessment to DB: {e}")

    return redirect(url_for('index'))


@app.route('/chart_data', methods=['GET'])
def chart_data():
    """Provides aggregated data for charts."""
    coll = get_db_collection()
    # --- This check was already correct ---
    if coll is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        # Refined pipeline for potentially empty collections
        pipeline = [
             {
                 '$facet': {
                     'labelCounts': [
                         {'$match': {'labels': {'$exists': True}}},
                         {'$group': {
                             '_id': None,
                             'humanity_threatening': {'$sum': {'$cond': [{'$eq': ['$labels.is_humanity_threatening', True]}, 1, 0]}},
                             'bypasses_eu_laws': {'$sum': {'$cond': [{'$eq': ['$labels.bypasses_eu_laws', True]}, 1, 0]}},
                             'gender_biased': {'$sum': {'$cond': [{'$eq': ['$labels.is_gender_biased', True]}, 1, 0]}}
                         }}
                     ],
                     'flagCounts': [
                         {'$match': {'flag_color': {'$exists': True, '$ne': None}}}, # Ensure flag_color exists and is not None
                         {'$group': {'_id': '$flag_color', 'count': {'$sum': 1}}}
                     ]
                 }
             }
         ]
        results = list(coll.aggregate(pipeline))

        # Process results robustly
        label_data = {'Humanity Threatening': 0, 'Bypasses EU Laws': 0, 'Gender Biased': 0}
        if results and results[0]['labelCounts']: # Check if labelCounts array is not empty
            counts = results[0]['labelCounts'][0] # Access the first element (the grouped result)
            label_data['Humanity Threatening'] = counts.get('humanity_threatening', 0)
            label_data['Bypasses EU Laws'] = counts.get('bypasses_eu_laws', 0)
            label_data['Gender Biased'] = counts.get('gender_biased', 0)

        flag_data_list = results[0]['flagCounts'] if results and results[0]['flagCounts'] else []
        flag_data = {item['_id']: item['count'] for item in flag_data_list if item.get('_id')}

        all_flags = ['Red', 'Orange', 'Green']
        final_flag_data = {flag: flag_data.get(flag, 0) for flag in all_flags}

        return jsonify({
            'labels': list(label_data.keys()),
            'label_values': list(label_data.values()),
            'flags': list(final_flag_data.keys()),
            'flag_values': list(final_flag_data.values())
        })

    except Exception as e:
        logging.error(f"Error fetching chart data: {e}")
        return jsonify({"error": f"Failed to fetch chart data: {e}"}), 500

# --- Main Execution ---
if __name__ == '__main__':
    # Setup logging (moved here for clarity)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("Starting AI Threat Assessor application...")

    # Attempt initial DB connection check at startup
    if get_db_collection() is None:
         logging.warning("Initial MongoDB connection check failed. Will retry on request.")
    else:
         logging.info("Initial MongoDB connection check successful.")

    # Set debug=False when using a production server like Gunicorn/Waitress managed by PM2
    app.run(debug=False, host='0.0.0.0', port=5000)