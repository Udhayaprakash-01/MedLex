# --- START OF FILE app.py ---

import os
import datetime
from datetime import timezone # Import timezone
import jwt
import logging
import time # Needed for excel lock wait
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import joinedload # For eager loading relationships
from sqlalchemy import or_ # Import or_ for searches
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Excel and Plotting Imports
import pandas as pd
from openpyxl import load_workbook # Technically pandas uses openpyxl, but good to be explicit if needed
import matplotlib # Import base library
matplotlib.use('Agg') # Use non-interactive backend suitable for web servers
import matplotlib.pyplot as plt
import io # To save plot to memory buffer
# import base64 # Not using base64 for now, using file URL

# AI Imports
import google.generativeai as genai
import google.ai.generativelanguage as glm # For function calling types
from google.generativeai.types import GenerationConfig, HarmCategory, HarmBlockThreshold

# --- Configuration ---
load_dotenv() # Load environment variables from .env file FIRST

# Initialize Flask App
app = Flask(__name__, template_folder="templates", static_folder="static")

# Database Configuration
# Use instance folder for DB and ensure it exists
if not os.path.exists(app.instance_path):
    try: os.makedirs(app.instance_path)
    except OSError: pass # Can fail if directory exists due to race condition
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(app.instance_path, "hospisys_app.db")}')
logging.info(f"Using database at: {app.config['SQLALCHEMY_DATABASE_URI']}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('SECRET_KEY', 'fallback_very_secret_key_please_change')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', os.path.join(app.instance_path, 'uploads')) # Store uploads in instance folder too

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'])
        print(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
    except OSError as e:
        print(f"Error creating upload folder {app.config['UPLOAD_FOLDER']}: {e}")

# Excel File Path (using instance folder for better portability)
EXCEL_FILE_PATH = os.path.join(app.instance_path, 'patient_visit_log.xlsx')
excel_dir = os.path.dirname(EXCEL_FILE_PATH)
if not os.path.exists(excel_dir):
    try:
        os.makedirs(excel_dir)
        logging.info(f"Created directory for Excel log: {excel_dir}")
    except OSError as e:
         logging.error(f"Error creating directory {excel_dir}: {e}")

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'pdf'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize Database & Migration Engine
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Logging ---
logging.basicConfig(level=logging.INFO if os.getenv('FLASK_ENV') != 'development' else logging.DEBUG,
                    format='%(asctime)s %(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

# --- Configure Gemini ---
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
logger.debug(f"--- DEBUG: Read GEMINI_API_KEY from environment: '{'Exists' if GEMINI_API_KEY else 'Not Found'}' ---")

gemini_configured = False
if not GEMINI_API_KEY:
    logging.warning("GEMINI_API_KEY not found in environment variables. AI features will be disabled.")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_configured = True
        logging.info("Gemini API configured successfully.")
    except Exception as e:
        logging.error(f"Error configuring Gemini API: {e}", exc_info=True)


# --- Database Models (with Timezone Updates) ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False) # Consider increasing length for stronger hashes
    role = db.Column(db.String(20), nullable=False)
    def set_password(self, password): self.password = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password, password)

class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    patient_identifier = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=True)
    contact_info = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc))
    # Relationships
    visits = db.relationship('Visit', backref='patient', lazy='dynamic', cascade="all, delete-orphan")
    prescriptions = db.relationship('Prescription', backref='patient', lazy='dynamic', cascade="all, delete-orphan")
    reports = db.relationship('Report', backref='patient', lazy='dynamic', cascade="all, delete-orphan")
    def to_dict(self): return { 'id': self.id, 'patient_identifier': self.patient_identifier, 'name': self.name, 'dob': self.dob.isoformat() if self.dob else None, 'contact_info': self.contact_info, 'created_at': self.created_at.isoformat() if self.created_at else None }
    def to_summary_dict(self): return { 'patient_id': self.id, 'patient_identifier': self.patient_identifier, 'name': self.name, 'dob': self.dob.isoformat() if self.dob else 'N/A' }

class Visit(db.Model):
    __tablename__ = 'visits'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False, index=True)
    visit_datetime = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc), index=True)
    reason = db.Column(db.Text, nullable=True)
    recorded_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Relationships
    recorded_by = db.relationship('User') # Eager load usually not needed unless displaying recorder name often
    prescriptions = db.relationship('Prescription', backref='visit', lazy='dynamic')
    reports = db.relationship('Report', backref='visit', lazy='dynamic')
    def to_dict(self): return { 'id': self.id, 'patient_id': self.patient_id, 'visit_datetime': self.visit_datetime.isoformat() if self.visit_datetime else None, 'reason': self.reason, 'recorded_by_id': self.recorded_by_id }
    def to_summary_dict(self):
        recorder_username = 'Unknown'
        if self.recorded_by: # Check if relationship is loaded
            recorder_username = self.recorded_by.username
        # Alternatively, fetch if needed (but can cause N+1 if not careful)
        # elif self.recorded_by_id:
        #     user = db.session.get(User, self.recorded_by_id)
        #     if user: recorder_username = user.username

        return {
            'visit_id': self.id,
            'visit_datetime': self.visit_datetime.isoformat() if self.visit_datetime else None,
            'reason': self.reason or 'N/A',
            'recorded_by': recorder_username
        }


class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    visit_id = db.Column(db.Integer, db.ForeignKey('visits.id', ondelete='SET NULL'), nullable=True, index=True) # Keep prescription if visit deleted?
    medication = db.Column(db.Text, nullable=False)
    dosage = db.Column(db.String(100), nullable=True)
    instructions = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc), index=True)
    # Relationships
    doctor = db.relationship('User')
    def to_dict(self): return { 'id': self.id, 'patient_id': self.patient_id, 'doctor_id': self.doctor_id, 'visit_id': self.visit_id, 'medication': self.medication, 'dosage': self.dosage, 'instructions': self.instructions, 'created_at': self.created_at.isoformat() if self.created_at else None }
    def to_summary_dict(self):
        doctor_username = self.doctor.username if self.doctor else 'Unknown'
        return {
            'prescription_id': self.id,
            'medication': self.medication,
            'dosage': self.dosage or 'N/A',
            'instructions': self.instructions or 'N/A',
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'prescribed_by_doctor_id': self.doctor_id,
            'doctor_username': doctor_username,
            'visit_id': self.visit_id
         }

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='CASCADE'), nullable=False, index=True)
    lab_technician_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    visit_id = db.Column(db.Integer, db.ForeignKey('visits.id', ondelete='SET NULL'), nullable=True, index=True) # Keep report if visit deleted?
    report_type = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False) # Store only the unique filename relative to UPLOAD_FOLDER
    uploaded_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc), index=True)
    # Relationships
    lab_technician = db.relationship('User')
    def get_safe_file_url(self):
        # Basic check to prevent unintended path components if file_path was somehow manipulated
        safe_filename = secure_filename(self.file_path) if self.file_path else ''
        return f'/uploads/{safe_filename}' if safe_filename else None

    def to_dict(self):
        file_url = self.get_safe_file_url()
        return {
            'id': self.id, 'patient_id': self.patient_id, 'lab_technician_id': self.lab_technician_id,
            'visit_id': self.visit_id, 'report_type': self.report_type,
            'file_url': file_url, # Use the safe URL
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None
        }
    def to_summary_dict(self):
        tech_username = self.lab_technician.username if self.lab_technician else 'Unknown'
        file_url = self.get_safe_file_url()
        return {
            'report_id': self.id, 'report_type': self.report_type,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'file_url': file_url, # Use the safe URL
            'uploaded_by_technician_id': self.lab_technician_id,
            'technician_username': tech_username, 'visit_id': self.visit_id
        }

# --- Excel Helper Functions ---

def append_to_excel(file_path, data_dict):
    """Appends a dictionary as a new row to an Excel file with basic locking."""
    df_new = pd.DataFrame([data_dict])
    lock_file = file_path + ".lock" # Simple file-based lock

    # Basic lock mechanism (not foolproof across processes/threads without more robust library)
    # Consider using a proper locking library like `filelock` for production
    max_wait_time = 5 # seconds
    wait_interval = 0.2 # seconds
    waited_time = 0
    while os.path.exists(lock_file):
        if waited_time >= max_wait_time:
            logger.warning(f"Excel file {file_path} lock wait timeout exceeded. Skipping append.")
            return
        time.sleep(wait_interval)
        waited_time += wait_interval
        logger.debug(f"Waiting for lock file {lock_file}...")


    try:
        # Create lock file
        with open(lock_file, 'w') as lf: lf.write('locked')

        # Use ExcelWriter in append mode or read/concat
        try:
            # More robust append using pandas read/concat
            df_existing = pd.read_excel(file_path, engine='openpyxl')
            # Ensure columns match, add missing ones with None if necessary
            all_cols = set(df_existing.columns) | set(df_new.columns)
            df_existing = df_existing.reindex(columns=all_cols)
            df_new = df_new.reindex(columns=all_cols)
            df_combined = pd.concat([df_existing, df_new], ignore_index=True)
            # Keep date format consistent - try converting back if pandas changed it
            if 'VisitDateTimeUTC' in df_combined.columns:
                 # Ensure timezone info is preserved if possible, format as ISO string
                 # Use .dt.strftime only if the column contains actual datetime objects
                 if pd.api.types.is_datetime64_any_dtype(df_combined['VisitDateTimeUTC']):
                     df_combined['VisitDateTimeUTC'] = df_combined['VisitDateTimeUTC'].dt.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                 else: # Handle cases where it might be strings already
                     pass # Assume strings are already in correct format

            df_combined.to_excel(file_path, index=False, engine='openpyxl')
            logger.debug(f"Appended data to existing Excel: {file_path}")
        except FileNotFoundError:
            # If file doesn't exist, write with header
            df_new.to_excel(file_path, index=False, engine='openpyxl')
            logger.info(f"Created new Excel log file: {file_path}")
        except Exception as read_write_err:
             logger.error(f"Error during Excel read/write operation for {file_path}: {read_write_err}", exc_info=True)
             raise # Re-raise the error to be caught by the caller

    except Exception as e:
        logger.error(f"Failed to append data to Excel file {file_path}: {e}", exc_info=True)
        # Optionally re-raise or handle as needed
    finally:
        # Remove lock file
        if os.path.exists(lock_file):
            try: os.remove(lock_file)
            except OSError as rm_err: logger.error(f"Error removing lock file {lock_file}: {rm_err}")


def _read_excel_safe(file_path):
    """Safely reads the Excel file, returning an empty DataFrame on error."""
    try:
        df = pd.read_excel(file_path, engine='openpyxl')
        # Ensure DateTime column is parsed correctly, trying common formats
        if 'VisitDateTimeUTC' in df.columns:
            # Try ISO format first, then fall back to letting pandas infer
            try:
                # Attempt parsing with timezone offset if present
                 df['VisitDateTimeUTC'] = pd.to_datetime(df['VisitDateTimeUTC'], errors='coerce', utc=True)
            except Exception: # Catch broader errors during parsing
                 df['VisitDateTimeUTC'] = pd.to_datetime(df['VisitDateTimeUTC'], errors='coerce') # Fallback without explicit format

            # Crucially, ensure it's timezone-aware (assume UTC if not specified after parsing)
            if pd.api.types.is_datetime64_any_dtype(df['VisitDateTimeUTC']): # Check if it's a datetime type
                if df['VisitDateTimeUTC'].dt.tz is None:
                    # Localize naive times to UTC, inferring based on common patterns if needed
                    df['VisitDateTimeUTC'] = df['VisitDateTimeUTC'].dt.tz_localize('UTC', ambiguous='infer', nonexistent='shift_forward')
                else:
                    df['VisitDateTimeUTC'] = df['VisitDateTimeUTC'].dt.tz_convert('UTC') # Convert existing TZ to UTC
            else:
                logger.warning(f"Column 'VisitDateTimeUTC' in {file_path} could not be fully parsed as datetime.")


        return df
    except FileNotFoundError:
        logger.warning(f"Excel log file not found: {file_path}")
        return pd.DataFrame() # Return empty dataframe
    except Exception as e:
        logger.error(f"Error reading Excel file {file_path}: {e}", exc_info=True)
        return pd.DataFrame() # Return empty dataframe on other errors

# --- Authentication & Authorization Decorators ---

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            logger.warning("Auth failed: Token is missing!")
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            # Add leeway for minor clock differences
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'], leeway=datetime.timedelta(seconds=30))
            # Use Session.get() for potentially better performance/caching
            current_user = db.session.get(User, data.get('user_id'))
            if not current_user:
                logger.warning(f"Auth failed: User ID {data.get('user_id')} not found.")
                return jsonify({'message': 'User not found for this token!'}), 401
            # Optional: Check if role in token matches user's current role (if roles can change)
            # if current_user.role != data.get('role'):
            #     logger.warning(f"Auth failed: Role mismatch for user {current_user.username}. Token role: {data.get('role')}, DB role: {current_user.role}")
            #     return jsonify({'message': 'User role may have changed. Please log in again.'}), 401

        except jwt.ExpiredSignatureError:
            logger.warning("Auth failed: Token has expired!")
            return jsonify({'message': 'Token has expired! Please log in again.'}), 401
        except jwt.InvalidTokenError as e:
            logger.error(f"Auth failed: Invalid token! Error: {e}")
            return jsonify({'message': 'Invalid token! Please log in again.'}), 401
        except Exception as e:
            logger.error(f"Auth failed: Token validation error: {e}", exc_info=True)
            return jsonify({'message': 'Token validation failed!'}), 401
        # Pass the loaded user object to the decorated function
        return f(current_user, *args, **kwargs)
    return decorated

def role_required(roles):
    if not isinstance(roles, list): roles = [roles] # Allow single role string or list
    def decorator(f):
        @wraps(f)
        @token_required # Ensures token is valid and user exists first
        def decorated_function(current_user, *args, **kwargs):
            if current_user.role not in roles:
                logger.warning(f"Auth failed: User '{current_user.username}' ({current_user.role}) access denied for route requiring roles: {roles}")
                return jsonify({'message': f'Access denied! Requires role: {", ".join(roles)}'}), 403
            # Role is valid, proceed with the original function
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

# --- Gemini AI Helper Functions / Tools ---

# --- Database Tools (for specific patient history) ---
def _find_patient(identifier_or_name: str) -> dict | str:
    """[DB Tool] Finds ONE patient by unique identifier or name search."""
    logger.info(f"[AI Tool Called] _find_patient with query: '{identifier_or_name}'")
    try:
        # Prioritize exact identifier match first
        patient = Patient.query.filter(Patient.patient_identifier.ilike(identifier_or_name)).first()
        if not patient:
            # If no exact ID match, search by name (case-insensitive)
            patient = Patient.query.filter(Patient.name.ilike(f'%{identifier_or_name}%')).first()

        if patient:
            logger.info(f"[AI Tool Success] _find_patient found: ID={patient.id}, Identifier={patient.patient_identifier}")
            return patient.to_summary_dict() # Return summary info
        else:
            logger.warning(f"[AI Tool Result] _find_patient: Patient not found for '{identifier_or_name}'")
            # Return a string message for 'not found' - this will be wrapped later
            return f"Patient not found matching identifier or name '{identifier_or_name}' in the database."
    except Exception as e:
        logger.error(f"[AI Tool Error] _find_patient failed: {e}", exc_info=True)
        # Return a string message for errors - this will be wrapped later
        return f"Error searching database for patient: {e}"

def _get_patient_recent_visits(patient_identifier: str, limit: int = 5) -> list[dict] | str:
    """[DB Tool] Gets recent detailed visits (reason, recorder) for a SPECIFIC patient identifier from the DATABASE."""
    logger.info(f"[AI Tool Called] _get_patient_recent_visits (DB) for: {patient_identifier}, limit={limit}")
    if not isinstance(limit, int) or limit <= 0: limit = 5
    try:
        patient = Patient.query.filter(Patient.patient_identifier.ilike(patient_identifier)).first()
        if not patient: return f"Patient with identifier '{patient_identifier}' not found in the database." # Return string

        # Eager load the 'recorded_by' relationship to avoid N+1 queries
        visits = patient.visits.options(joinedload(Visit.recorded_by)).order_by(Visit.visit_datetime.desc()).limit(limit).all()

        if visits:
             logger.info(f"[AI Tool Success] _get_patient_recent_visits (DB) found {len(visits)} visits.")
             return [v.to_summary_dict() for v in visits] # Return list of dicts
        else:
             logger.info(f"[AI Tool Result] _get_patient_recent_visits (DB): No visits found for {patient_identifier}")
             return f"No visits found in database for patient '{patient_identifier}'." # Return string
    except Exception as e:
        logger.error(f"[AI Tool Error] _get_patient_recent_visits (DB) failed: {e}", exc_info=True)
        return f"Error retrieving database visits for '{patient_identifier}': {e}" # Return string

def _get_patient_prescriptions(patient_identifier: str, limit: int = 10) -> list[dict] | str:
    """[DB Tool] Gets prescriptions for a SPECIFIC patient identifier from the DATABASE."""
    logger.info(f"[AI Tool Called] _get_patient_prescriptions (DB) for: {patient_identifier}, limit={limit}")
    if not isinstance(limit, int) or limit <= 0: limit = 10
    try:
        patient = Patient.query.filter(Patient.patient_identifier.ilike(patient_identifier)).first()
        if not patient: return f"Patient with identifier '{patient_identifier}' not found in the database." # Return string

        # Eager load doctor relationship
        prescriptions = patient.prescriptions.options(joinedload(Prescription.doctor)).order_by(Prescription.created_at.desc()).limit(limit).all()

        if prescriptions:
            logger.info(f"[AI Tool Success] _get_patient_prescriptions (DB) found {len(prescriptions)} prescriptions.")
            return [p.to_summary_dict() for p in prescriptions] # Return list of dicts
        else:
            logger.info(f"[AI Tool Result] _get_patient_prescriptions (DB): No prescriptions found for {patient_identifier}")
            return f"No prescriptions found in database for patient '{patient_identifier}'." # Return string
    except Exception as e:
        logger.error(f"[AI Tool Error] _get_patient_prescriptions (DB) failed: {e}", exc_info=True)
        return f"Error retrieving database prescriptions for '{patient_identifier}': {e}" # Return string

def _get_patient_reports(patient_identifier: str, limit: int = 10) -> list[dict] | str:
    """[DB Tool] Gets report summaries (type, date, URL) for a SPECIFIC patient identifier from the DATABASE."""
    logger.info(f"[AI Tool Called] _get_patient_reports (DB) for: {patient_identifier}, limit={limit}")
    if not isinstance(limit, int) or limit <= 0: limit = 10
    try:
        patient = Patient.query.filter(Patient.patient_identifier.ilike(patient_identifier)).first()
        if not patient: return f"Patient with identifier '{patient_identifier}' not found in the database." # Return string

        # Eager load technician relationship
        reports = patient.reports.options(joinedload(Report.lab_technician)).order_by(Report.uploaded_at.desc()).limit(limit).all()

        if reports:
            logger.info(f"[AI Tool Success] _get_patient_reports (DB) found {len(reports)} reports.")
            return [r.to_summary_dict() for r in reports] # Return list of dicts
        else:
             logger.info(f"[AI Tool Result] _get_patient_reports (DB): No reports found for {patient_identifier}")
             return f"No reports found in database for patient '{patient_identifier}'." # Return string
    except Exception as e:
        logger.error(f"[AI Tool Error] _get_patient_reports (DB) failed: {e}", exc_info=True)
        return f"Error retrieving database reports for '{patient_identifier}': {e}" # Return string

# --- Excel Log Tools (for aggregate/overview data) ---
def _get_recent_visits_from_excel(limit: int = 5) -> list[dict] | str:
    """[Excel Tool] Gets the most recent visit entries across ALL patients from the EXCEL log."""
    logger.info(f"[AI Tool Called] _get_recent_visits_from_excel (Excel) limit={limit}")
    if not isinstance(limit, int) or limit <= 0: limit = 5
    df = _read_excel_safe(EXCEL_FILE_PATH)
    if df.empty: return "Visit log Excel file is empty or could not be read." # Return string

    # Ensure the datetime column exists and sort
    if 'VisitDateTimeUTC' in df.columns and pd.api.types.is_datetime64_any_dtype(df['VisitDateTimeUTC']) and not df['VisitDateTimeUTC'].isnull().all():
         # Drop rows where date parsing failed if any, before sorting
        df_valid_dates = df.dropna(subset=['VisitDateTimeUTC'])
        if df_valid_dates.empty: return "No valid visit date entries found in the log after cleaning." # Return string
        df_recent = df_valid_dates.sort_values(by='VisitDateTimeUTC', ascending=False).head(limit)
    elif not df.empty: # If no date column, return last rows added
        df_recent = df.tail(limit)
        logger.warning("[AI Tool Warning] _get_recent_visits_from_excel: 'VisitDateTimeUTC' column missing or not datetime. Returning last rows based on order.")
    else: return "No valid visit data found in the log." # Return string


    # Select and format relevant columns for output
    relevant_cols = ['PatientID', 'PatientName', 'VisitDateTimeUTC', 'RecordedByUsername']
    output_data = []
    for index, row in df_recent.iterrows():
        entry = {}
        for col in relevant_cols:
            value = row.get(col) # Use .get for safety in case columns change
            if pd.isna(value): entry[col] = 'N/A'
            elif isinstance(value, (datetime.datetime, pd.Timestamp)):
                # Provide a readable format, indicating timezone if possible
                try:
                    # Ensure timezone info is present before formatting
                    ts_aware = value if value.tzinfo else value.tz_localize('UTC', ambiguous='infer', nonexistent='shift_forward')
                    # Format without microseconds for slightly cleaner output
                    entry[col] = ts_aware.strftime('%Y-%m-%d %H:%M:%S %Z').strip()
                except Exception: entry[col] = str(value) # Fallback
            else: entry[col] = str(value) # Ensure value is stringifiable
        output_data.append(entry)

    if not output_data: return "No recent visits found after filtering." # Return string
    logger.info(f"[AI Tool Success] _get_recent_visits_from_excel (Excel) found {len(output_data)} visits.")
    return output_data # Return list of dicts

def _get_visit_counts_from_excel(period: str = 'today') -> dict | str:
    """[Excel Tool] Counts TOTAL visits logged in the EXCEL file for a given period ('today', 'yesterday', 'last_7_days', 'current_month')."""
    logger.info(f"[AI Tool Called] _get_visit_counts_from_excel (Excel) period={period}")
    df = _read_excel_safe(EXCEL_FILE_PATH)
    if df.empty or 'VisitDateTimeUTC' not in df.columns or not pd.api.types.is_datetime64_any_dtype(df['VisitDateTimeUTC']) or df['VisitDateTimeUTC'].isnull().all():
        return "Visit log Excel file is empty, unreadable, or missing valid 'VisitDateTimeUTC' data." # Return string

    now_utc = datetime.datetime.now(timezone.utc)
    # Drop rows where date conversion might have failed
    df = df.dropna(subset=['VisitDateTimeUTC'])
    if df.empty: return f"No valid visit date entries found in the log for period '{period}'." # Return string

    df_filtered = pd.DataFrame()

    try:
        # Datetime column should already be timezone-aware UTC from _read_excel_safe
        if period == 'today':
            start_dt = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
            df_filtered = df[df['VisitDateTimeUTC'] >= start_dt]
        elif period == 'yesterday':
            today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
            start_dt = today_start - datetime.timedelta(days=1)
            end_dt = today_start - datetime.timedelta(microseconds=1) # End is just before today starts
            df_filtered = df[(df['VisitDateTimeUTC'] >= start_dt) & (df['VisitDateTimeUTC'] <= end_dt)]
        elif period == 'last_7_days':
            # Include today in the last 7 days
            start_dt = (now_utc - datetime.timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
            df_filtered = df[df['VisitDateTimeUTC'] >= start_dt]
        elif period == 'current_month':
            start_dt = now_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            df_filtered = df[df['VisitDateTimeUTC'] >= start_dt]
        else:
            logger.warning(f"[AI Tool Param Error] Invalid period '{period}' for visit counts.")
            return f"Invalid period specified: '{period}'. Use 'today', 'yesterday', 'last_7_days', or 'current_month'." # Return string

        count = len(df_filtered)
        logger.info(f"[AI Tool Success] _get_visit_counts_from_excel (Excel) found {count} visits for period '{period}'.")
        return {'period': period, 'visit_count': count} # Return dict

    except Exception as e:
         logger.error(f"[AI Tool Error] Error calculating counts from Excel for period '{period}': {e}", exc_info=True)
         return f"Error processing visit counts from Excel log for period '{period}'." # Return string

def _generate_visit_graph_from_excel(period: str = 'last_7_days') -> dict | str:
    """[Excel Tool] Generates a bar chart of daily visits from EXCEL log for a period ('last_7_days', 'last_30_days', 'current_month') and returns its URL."""
    logger.info(f"[AI Tool Called] _generate_visit_graph_from_excel (Excel) period={period}")
    UPLOAD_FOLDER = app.config['UPLOAD_FOLDER'] # Get path from app config
    df = _read_excel_safe(EXCEL_FILE_PATH)
    if df.empty or 'VisitDateTimeUTC' not in df.columns or not pd.api.types.is_datetime64_any_dtype(df['VisitDateTimeUTC']) or df['VisitDateTimeUTC'].isnull().all():
        return "Visit log Excel file is empty, unreadable, or missing valid 'VisitDateTimeUTC' data for graphing." # Return string

    now_utc = datetime.datetime.now(timezone.utc)
    start_date_utc = None
    title_period = period.replace('_', ' ').title()
    title = f"Daily Visits ({title_period})"

    # Drop rows where date conversion might have failed
    df = df.dropna(subset=['VisitDateTimeUTC'])
    if df.empty: return "No valid visit date entries found in the log for graphing." # Return string

    fig = None # Initialize fig to None
    try:
        # Datetime column should be timezone-aware UTC from _read_excel_safe
        if period == 'last_7_days':
            # Including today
            start_date_utc = (now_utc - datetime.timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'last_30_days':
             # Including today
             start_date_utc = (now_utc - datetime.timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
             title = "Daily Visits (Last 30 Days)"
        elif period == 'current_month':
             start_date_utc = now_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
             title = "Daily Visits (Current Month)"
        else:
            logger.warning(f"[AI Tool Param Error] Invalid period '{period}' for visit graph.")
            return f"Invalid period for graph: '{period}'. Use 'last_7_days', 'last_30_days', 'current_month'." # Return string

        # Filter data for the period
        df_period = df[df['VisitDateTimeUTC'] >= start_date_utc].copy() # Use .copy() to avoid SettingWithCopyWarning
        if df_period.empty:
            logger.info(f"[AI Tool Result] No visit data found in Excel log for the period '{period}' to generate a graph.")
            return f"No visit data found in the log for the period '{period}' to generate a graph." # Return string

        # Extract date part *after* filtering
        df_period['VisitDate'] = df_period['VisitDateTimeUTC'].dt.date
        daily_counts = df_period.groupby('VisitDate').size()

        # Create a full date range for the x-axis (using date objects)
        end_date_for_range = now_utc.date() # Use today's date as end
        all_dates_in_period = pd.date_range(start=start_date_utc.date(), end=end_date_for_range, freq='D').date
        # Reindex to include days with zero visits, fill with 0
        daily_counts = daily_counts.reindex(all_dates_in_period, fill_value=0)

        if daily_counts.empty:
             logger.info(f"[AI Tool Result] Daily counts calculation resulted in empty series for period '{period}'.")
             return f"Could not generate graph counts for the period '{period}'." # Return string

        # Generate Plot
        fig, ax = plt.subplots(figsize=(12, 6)) # Use fig, ax pattern
        daily_counts.plot(kind='bar', ax=ax, color='#3498db') # Use a specific color
        ax.set_title(title, fontsize=16)
        ax.set_xlabel("Date", fontsize=12)
        ax.set_ylabel("Number of Visits", fontsize=12)
        ax.tick_params(axis='x', rotation=45, labelsize=10)
        ax.tick_params(axis='y', labelsize=10)
        ax.grid(axis='y', linestyle='--', alpha=0.7) # Add subtle grid lines
        # Format x-axis labels to show date only
        ax.set_xticklabels([d.strftime('%Y-%m-%d') for d in daily_counts.index], rotation=45, ha='right')
        plt.tight_layout() # Adjust layout

        # Save Plot to File in Upload Folder
        timestamp = now_utc.strftime("%Y%m%d%H%M%S")
        filename = f"visits_graph_{period}_{timestamp}.png"
        # Ensure upload folder exists (it should from startup, but check again)
        if not os.path.exists(UPLOAD_FOLDER):
            try: os.makedirs(UPLOAD_FOLDER)
            except OSError: logger.error(f"Failed to create upload folder {UPLOAD_FOLDER} during graph generation.") # Should not happen if startup worked

        save_path = os.path.join(UPLOAD_FOLDER, filename)
        plt.savefig(save_path, dpi=100) # Save the figure
        plt.close(fig) # CRITICAL: Close the figure to release memory
        fig = None # Ensure fig is None after closing

        # Return URL
        file_url = f'/uploads/{filename}' # Relative URL for the browser
        logger.info(f"[AI Tool Success] Generated graph: {save_path}, URL: {file_url}")
        return {'graph_description': title, 'graph_url': file_url} # Return dict

    except Exception as e:
        if fig: plt.close(fig) # Ensure plot is closed on error if it was created
        logger.error(f"[AI Tool Error] Error generating graph for period '{period}': {e}", exc_info=True)
        return f"Error generating visit graph from Excel log for '{period}'." # Return string


# --- AI Model Setup ---
model = None
if gemini_configured:
    try:
        # Define the tools for the model
        # Group tools logically for clarity
        db_tools = [
            _find_patient,
            _get_patient_recent_visits,
            _get_patient_prescriptions,
            _get_patient_reports,
        ]
        excel_tools = [
            _get_recent_visits_from_excel,
            _get_visit_counts_from_excel,
            _generate_visit_graph_from_excel
        ]
        gemini_tools = db_tools + excel_tools

        # Tool configuration for Gemini (if needed for complex types, though basic types often work)
        # tool_config = {"function_calling_config": {"mode": "ANY"}} # Or AUTO

        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash", # Or "gemini-1.5-pro" or your preferred model
            tools=gemini_tools,
            # tool_config=tool_config, # If using specific config
            safety_settings = { # Adjust safety settings as needed
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            }
            # System instruction can be set here or added to the chat history later
            # system_instruction="You are HospiSys AI..."
        )
        logger.info(f"Gemini Model '{model.model_name}' with {len(gemini_tools)} tools initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize Gemini model: {e}", exc_info=True)
        gemini_configured = False
        model = None # Ensure model is None if init fails
else:
    logger.warning("Gemini model not initialized (API key missing or config failed). AI features disabled.")


# --- Standard Routes ---

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serves static files (CSS, JS, images)."""
    # Add cache control headers for static files if desired
    # response = send_from_directory(app.static_folder, filename)
    # response.headers['Cache-Control'] = 'public, max-age=3600' # Example: cache for 1 hour
    # return response
    return send_from_directory(app.static_folder, filename)


@app.route('/uploads/<path:filename>')
@token_required # Ensure user is logged in to access uploaded files
def uploaded_files(current_user, filename):
    """Serves uploaded files (reports, graphs) securely."""
    # Basic security: prevent directory traversal using Werkzeug's secure_filename
    # Although secure_filename primarily sanitizes, combining it with normpath provides defense.
    safe_filename = secure_filename(filename)
    if not safe_filename or '..' in safe_filename or safe_filename.startswith(('/', '\\')):
        logger.warning(f"Attempted potentially unsafe file access by {current_user.username}: {filename}")
        abort(404)

    try:
        # Securely construct the full path
        directory = os.path.abspath(app.config['UPLOAD_FOLDER'])
        file_path = os.path.normpath(os.path.join(directory, safe_filename))

        # Extra check: Ensure resolved path is still within the intended upload directory
        # Use os.path.commonpath (Python 3.5+) or check startswith carefully
        if os.path.commonpath([directory, file_path]) != directory:
             logger.error(f"Security violation: Path resolved outside upload folder. User: {current_user.username}, Requested: {filename}, Resolved: {file_path}")
             abort(404)

        logger.info(f"Serving file: {safe_filename} from {directory} for user {current_user.username}")
        # Let browser handle display (PDF, PNG) or download if unknown
        return send_from_directory(directory, safe_filename, as_attachment=False)
    except FileNotFoundError:
        logger.error(f"File not found: {safe_filename} in {directory}")
        abort(404)
    except Exception as e:
        logger.error(f"Error serving file {safe_filename}: {e}", exc_info=True)
        abort(500) # Internal server error

@app.route('/roles', methods=['GET'])
def get_roles():
    """Provides a list of valid roles for the login dropdown."""
    # Consider fetching from DB if roles were dynamic, but hardcoding is fine for fixed roles.
    return jsonify({'roles': ["superadmin", "doctor", "receptionist", "pharmacist", "labtechnician"]})

@app.route('/login', methods=['POST'])
def login():
    """Handles user login and returns a JWT token."""
    try:
        data = request.get_json()
        if not data: raise ValueError("No JSON data received.")
    except Exception:
        return jsonify({'message': 'Invalid JSON format!'}), 400

    required_fields = ['role', 'username', 'password']
    missing_fields = [f for f in required_fields if f not in data or not data[f]]
    if missing_fields:
        return jsonify({'message': f'Missing fields: {", ".join(missing_fields)}'}), 400

    username = data['username']
    password = data['password']
    role = data['role']

    # Find user by username and role
    user = User.query.filter_by(username=username, role=role).first()

    if user and user.check_password(password):
        try:
            # Token expires in 8 hours (adjust as needed)
            expiry = datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=8)
            token_payload = {
                'user_id': user.id,
                'role': user.role,
                'username': user.username,
                'exp': expiry,
                'iat': datetime.datetime.now(timezone.utc) # Issued at time
            }
            token = jwt.encode(token_payload, app.secret_key, algorithm='HS256')
            logger.info(f"Login successful: {username} ({role})")
            return jsonify({'token': token, 'role': user.role, 'username': user.username})
        except Exception as e:
            logger.error(f"JWT Encoding Error during login for {username}: {e}", exc_info=True)
            return jsonify({'message': 'Login failed: Could not generate authentication token.'}), 500
    else:
        # Generic message to avoid revealing which part (user/pass/role) was wrong
        logger.warning(f"Login failed for user attempt '{username}' (Role: {role}) - Invalid credentials or role mismatch.")
        return jsonify({'message': 'Invalid credentials or role!'}), 401

@app.route('/dashboard', methods=['GET'])
@token_required # Use decorator to verify token and get user
def dashboard(current_user):
    """A simple protected route to verify token and welcome user."""
    logger.info(f"Dashboard accessed by user: {current_user.username} ({current_user.role})")
    # You could potentially return role-specific dashboard data here if needed
    return jsonify({'message': f'Token valid. Welcome {current_user.username}! Your role is {current_user.role}.'})

# --- Feature Routes ---

@app.route('/patients/search', methods=['GET'])
@role_required(['receptionist', 'doctor', 'labtechnician', 'pharmacist', 'superadmin'])
def search_patient(current_user):
    """Searches for patients by identifier or name."""
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'message': 'Search query parameter "q" is required'}), 400

    # Limit search results for performance
    limit = int(request.args.get('limit', 15))
    if limit > 50: limit = 50 # Max limit

    try:
        # Case-insensitive search on identifier (exact match) OR name (partial match)
        search_term_like = f'%{query}%'
        patients = Patient.query.filter(or_(
            Patient.patient_identifier.ilike(query), # Exact identifier match (case-insensitive)
            Patient.name.ilike(search_term_like)     # Partial name match (case-insensitive)
        )).order_by(Patient.name).limit(limit).all()

        logger.info(f"Patient search by {current_user.username}: '{query}' -> Found {len(patients)} results.")
        # Return full patient dict for flexibility on the frontend
        return jsonify({'patients': [p.to_dict() for p in patients]})
    except Exception as e:
        logger.error(f"Patient search DB error for query '{query}' by {current_user.username}: {e}", exc_info=True)
        return jsonify({'message': 'Database error during patient search.'}), 500

@app.route('/patients', methods=['POST'])
@role_required(['receptionist', 'superadmin'])
def create_patient(current_user):
    """Creates a new patient record."""
    data = request.get_json()
    if not data: return jsonify({'message': 'Invalid JSON format!'}), 400

    identifier = data.get('patient_identifier', '').strip()
    name = data.get('name', '').strip()

    if not identifier or not name:
        return jsonify({'message': 'Patient Identifier and Name are required and cannot be empty'}), 400

    # Check if patient identifier already exists (case-insensitive)
    existing_patient = Patient.query.filter(Patient.patient_identifier.ilike(identifier)).first()
    if existing_patient:
        logger.warning(f"Attempt to create patient with existing identifier '{identifier}' by {current_user.username}")
        return jsonify({'message': f'Patient Identifier "{identifier}" already exists. Please use a unique identifier.'}), 409 # Conflict

    dob = None
    dob_str = data.get('dob')
    if dob_str:
        try:
            dob = datetime.datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'message': 'Invalid date format for Date of Birth. Please use YYYY-MM-DD.'}), 400

    try:
        new_patient = Patient(
            patient_identifier=identifier,
            name=name,
            dob=dob,
            contact_info=data.get('contact_info', '').strip() or None # Store None if empty
        )
        db.session.add(new_patient)
        db.session.commit()
        logger.info(f"Patient created successfully: ID={new_patient.id}, Identifier='{identifier}' by {current_user.username}")
        return jsonify({'message': 'Patient created successfully', 'patient': new_patient.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"DB error creating patient '{identifier}' by {current_user.username}: {e}", exc_info=True)
        return jsonify({'message': 'Database error occurred while creating the patient.'}), 500

@app.route('/visits', methods=['POST'])
@role_required(['receptionist', 'superadmin'])
def record_visit(current_user):
    """Records a patient visit in the database AND appends basic info to the Excel log."""
    data = request.get_json()
    if not data: return jsonify({'message': 'Invalid JSON format!'}), 400

    patient_id_str = data.get('patient_id')
    if not patient_id_str:
        return jsonify({'message': 'Patient ID is required'}), 400

    try: patient_id = int(patient_id_str)
    except ValueError: return jsonify({'message': 'Invalid Patient ID format. Must be an integer.'}), 400

    # Fetch the patient using Session.get()
    patient = db.session.get(Patient, patient_id)
    if not patient:
        logger.warning(f"Visit record attempt failed: Patient ID {patient_id} not found. User: {current_user.username}")
        return jsonify({'message': f'Patient with ID {patient_id} not found'}), 404

    try:
        # Use one consistent timestamp for both DB and Excel
        visit_time_utc = datetime.datetime.now(timezone.utc)

        # --- Save to Database ---
        new_visit = Visit(
            patient_id=patient.id,
            reason=data.get('reason', '').strip() or None, # Store None if empty
            recorded_by_id=current_user.id,
            visit_datetime=visit_time_utc
        )
        db.session.add(new_visit)
        # Flush to get the new_visit.id if needed before commit, but commit is usually sufficient
        db.session.commit()
        logger.info(f"Visit recorded in DB: ID {new_visit.id} for Patient ID {patient.id} ('{patient.patient_identifier}') by {current_user.username}")

        # --- Append to Excel (after successful DB commit) ---
        try:
             visit_data_for_excel = {
                 'VisitID': new_visit.id, # Include DB Visit ID
                 'PatientDB_ID': patient.id, # Include DB Patient ID
                 'PatientID': patient.patient_identifier, # The identifier used in UI/Search
                 'PatientName': patient.name,
                 'PatientDOB': patient.dob.isoformat() if patient.dob else None,
                 'VisitDateTimeUTC': visit_time_utc.isoformat(), # Use ISO 8601 format with TZ offset
                 'RecordedByUsername': current_user.username
                 # Add 'Reason' if needed in Excel, but keep it simple as requested
                 # 'Reason': new_visit.reason
             }
             append_to_excel(EXCEL_FILE_PATH, visit_data_for_excel)
             logger.info(f"Visit {new_visit.id} successfully appended to Excel log: {EXCEL_FILE_PATH}")
        except Exception as excel_err:
             # Log error but DO NOT fail the request if DB save succeeded.
             logger.error(f"CRITICAL: Failed to append Visit ID {new_visit.id} to Excel log '{EXCEL_FILE_PATH}' after DB save. Error: {excel_err}", exc_info=True)
             # Optionally: Implement a retry mechanism or flag for later processing
        # --- End Append to Excel ---

        return jsonify({'message': 'Visit recorded successfully in database and logged.', 'visit': new_visit.to_dict()}), 201

    except Exception as e:
        db.session.rollback() # Rollback DB changes if any part failed before commit or during commit
        logger.error(f"DB error recording visit for Patient ID {patient.id} by {current_user.username}: {e}", exc_info=True)
        return jsonify({'message': 'Database error occurred while recording the visit.'}), 500


@app.route('/patients/<int:patient_id>/history', methods=['GET'])
@role_required(['doctor', 'superadmin']) # Only doctors and superadmins can see full history
def get_patient_history(current_user, patient_id):
    """Retrieves the full history (visits, prescriptions, reports) for a specific patient."""
    patient = db.session.get(Patient, patient_id)
    if not patient:
        abort(404, description=f"Patient with ID {patient_id} not found")

    try:
        # Use joinedload for eager loading related user info to prevent N+1 queries
        visits = patient.visits.options(
            joinedload(Visit.recorded_by)
        ).order_by(Visit.visit_datetime.desc()).all()

        prescriptions = patient.prescriptions.options(
            joinedload(Prescription.doctor)
        ).order_by(Prescription.created_at.desc()).all()

        reports = patient.reports.options(
            joinedload(Report.lab_technician)
        ).order_by(Report.uploaded_at.desc()).all()

        # Prepare response data using to_dict methods
        history_data = {
            'patient': patient.to_dict(),
            'visits': [v.to_dict() for v in visits],
            'prescriptions': [p.to_dict() for p in prescriptions],
            'reports': [r.to_dict() for r in reports]
        }
        logger.info(f"Full history retrieved for Patient ID {patient_id} ('{patient.patient_identifier}') by {current_user.username}")
        return jsonify(history_data)
    except Exception as e:
        logger.error(f"DB error retrieving history for Patient ID {patient_id} by {current_user.username}: {e}", exc_info=True)
        return jsonify({'message': 'Database error retrieving patient history.'}), 500

@app.route('/prescriptions', methods=['POST'])
@role_required(['doctor']) # Only doctors can create prescriptions
def create_prescription(current_user):
    """Creates a new prescription for a patient."""
    data = request.get_json()
    if not data: return jsonify({'message': 'Invalid JSON format!'}), 400

    patient_id_str = data.get('patient_id')
    medication = data.get('medication', '').strip()

    if not patient_id_str or not medication:
        return jsonify({'message': 'Patient ID and Medication are required'}), 400

    try: patient_id = int(patient_id_str)
    except ValueError: return jsonify({'message': 'Invalid Patient ID format. Must be an integer.'}), 400

    patient = db.session.get(Patient, patient_id)
    if not patient:
        logger.warning(f"Prescription creation failed: Patient ID {patient_id} not found. User: {current_user.username}")
        return jsonify({'message': f'Patient with ID {patient_id} not found'}), 404

    # Optional: Associate with the latest visit?
    # latest_visit = patient.visits.order_by(Visit.visit_datetime.desc()).first()
    # visit_id = latest_visit.id if latest_visit else None
    # Or associate based on a visit_id passed from the frontend if needed

    try:
        new_prescription = Prescription(
            patient_id=patient.id,
            doctor_id=current_user.id, # The logged-in doctor creates it
            # visit_id=visit_id, # Uncomment if associating with latest visit
            medication=medication,
            dosage=data.get('dosage', '').strip() or None,
            instructions=data.get('instructions', '').strip() or None
        )
        db.session.add(new_prescription)
        db.session.commit()
        logger.info(f"Prescription created: ID {new_prescription.id} for Patient ID {patient.id} ('{patient.patient_identifier}') by Dr. {current_user.username}")
        return jsonify({'message': 'Prescription created successfully', 'prescription': new_prescription.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"DB error creating prescription for Patient ID {patient.id} by Dr. {current_user.username}: {e}", exc_info=True)
        return jsonify({'message': 'Database error creating prescription.'}), 500

@app.route('/patients/<int:patient_id>/prescriptions', methods=['GET'])
@role_required(['pharmacist', 'doctor', 'superadmin']) # Roles who can view prescriptions
def get_patient_prescriptions(current_user, patient_id):
    """Retrieves all prescriptions for a specific patient."""
    patient = db.session.get(Patient, patient_id)
    if not patient:
        abort(404, description=f"Patient with ID {patient_id} not found")

    try:
        # Eager load the doctor who prescribed
        prescriptions = patient.prescriptions.options(
            joinedload(Prescription.doctor)
        ).order_by(Prescription.created_at.desc()).all()

        response_data = {
            'patient': patient.to_dict(),
            'prescriptions': [p.to_dict() for p in prescriptions]
        }
        logger.info(f"Prescriptions retrieved for Patient ID {patient_id} ('{patient.patient_identifier}') by {current_user.username} ({current_user.role})")
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"DB error retrieving prescriptions for Patient ID {patient_id} by {current_user.username}: {e}", exc_info=True)
        return jsonify({'message': 'Database error retrieving prescriptions.'}), 500

@app.route('/reports', methods=['POST'])
@role_required(['labtechnician', 'superadmin'])
def upload_report(current_user):
    """Handles file upload for lab reports."""
    # Check if the post request has the file part
    if 'report_file' not in request.files:
        return jsonify({'message': 'No file part named "report_file" in the request'}), 400
    file = request.files['report_file']

    # Check form fields
    patient_id_str = request.form.get('patient_id')
    report_type = request.form.get('report_type', '').strip()

    if not patient_id_str or not report_type:
        return jsonify({'message': 'Patient ID and Report Type form fields are required'}), 400
    if file.filename == '':
        return jsonify({'message': 'No file selected for upload'}), 400

    try: patient_id = int(patient_id_str)
    except ValueError: return jsonify({'message': 'Invalid Patient ID format. Must be an integer.'}), 400

    patient = db.session.get(Patient, patient_id)
    if not patient:
        logger.warning(f"Report upload failed: Patient ID {patient_id} not found. User: {current_user.username}")
        return jsonify({'message': f'Patient with ID {patient_id} not found'}), 404

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename); # Sanitize filename
        # Create a unique filename to prevent overwrites and ensure validity
        timestamp = datetime.datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        safe_report_type = "".join(c if c.isalnum() else "_" for c in report_type)[:30] # Sanitize report type for filename
        # Construct unique filename: timestamp_patientID_reportType_originalFilename.pdf
        unique_filename = f"{timestamp}_{patient.patient_identifier}_{safe_report_type}_{original_filename}"
        file_path_full = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Optional: Associate with the latest visit?
        # latest_visit = patient.visits.order_by(Visit.visit_datetime.desc()).first()
        # visit_id = latest_visit.id if latest_visit else None

        file_saved = False
        try:
            # Ensure upload folder exists just in case
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(file_path_full);
            file_saved = True
            logger.info(f"Report file saved: {file_path_full} for Patient ID {patient.id} by {current_user.username}")

            # Save metadata to database
            new_report = Report(
                patient_id=patient.id,
                lab_technician_id=current_user.id,
                # visit_id=visit_id, # Uncomment if associating with visit
                report_type=report_type,
                file_path=unique_filename # Store only the unique filename relative to UPLOAD_FOLDER
            )
            db.session.add(new_report)
            db.session.commit()
            logger.info(f"Report DB record created: ID {new_report.id} ('{report_type}') for Patient ID {patient.id} by {current_user.username}")
            return jsonify({'message': f'Report "{report_type}" uploaded successfully', 'report': new_report.to_dict()}), 201

        except Exception as e:
            db.session.rollback() # Rollback DB changes if file save or DB commit failed
            logger.error(f"Error saving file/DB record for report upload. Patient ID {patient.id}, Type '{report_type}', User {current_user.username}. Error: {e}", exc_info=True)
            # If file was saved but DB failed, try to clean up the orphaned file
            if file_saved and os.path.exists(file_path_full):
                try:
                    os.remove(file_path_full)
                    logger.info(f"Cleaned up orphaned upload file: {file_path_full}")
                except OSError as ose:
                    logger.error(f"Error removing orphaned upload file {file_path_full}: {ose}", exc_info=True)
            return jsonify({'message': 'Server error during report upload process.'}), 500
    elif file and not allowed_file(file.filename):
         extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'N/A'
         logger.warning(f"Report upload rejected for Patient ID {patient_id} by {current_user.username}: Invalid file type '{extension}' (Filename: '{file.filename}')")
         return jsonify({'message': f'File type "{extension}" not allowed. Only PDF files ({", ".join(ALLOWED_EXTENSIONS)}) are permitted.'}), 400
    else:
        # Should not happen if checks above are correct, but as a fallback
        return jsonify({'message': 'Unexpected error during file check.'}), 400


@app.route('/users', methods=['GET'])
@role_required(['superadmin']) # Only superadmin can view all users
def get_all_users(current_user):
     """Retrieves a list of all registered users."""
     try:
         # Order users for consistent display
         users = User.query.order_by(User.role, User.username).all()
         # Return only non-sensitive user information
         user_list = [{'id': u.id, 'username': u.username, 'role': u.role} for u in users]
         logger.info(f"Superadmin {current_user.username} retrieved list of {len(user_list)} users.")
         return jsonify({'users': user_list})
     except Exception as e:
         logger.error(f"DB error retrieving users list by {current_user.username}: {e}", exc_info=True)
         return jsonify({'message': 'Database error retrieving users list.'}), 500


# --- AI Assistant Route ---
@app.route('/ask-ai', methods=['POST'])
@role_required(['doctor', 'superadmin']) # Roles allowed to use the AI assistant
def ask_ai_assistant(current_user):
    """Handles queries to the Gemini AI assistant with function calling."""
    if not model:
        logger.error(f"AI request failed: Model not available/configured. User: {current_user.username}")
        return jsonify({'error': 'AI Assistant is currently unavailable. Please check configuration.'}), 503 # Service Unavailable

    data = request.get_json()
    user_query = data.get('query', '').strip() if data else ''
    if not user_query:
        return jsonify({'error': 'No query provided.'}), 400

    logger.info(f"AI query received from {current_user.username} (Role: {current_user.role}): '{user_query[:100]}...'") # Log snippet

    # Tool binding (map function names to actual Python functions)
    available_tools = {
        # DB tools
        "_find_patient": _find_patient,
        "_get_patient_recent_visits": _get_patient_recent_visits,
        "_get_patient_prescriptions": _get_patient_prescriptions,
        "_get_patient_reports": _get_patient_reports,
        # Excel tools
        "_get_recent_visits_from_excel": _get_recent_visits_from_excel,
        "_get_visit_counts_from_excel": _get_visit_counts_from_excel,
        "_generate_visit_graph_from_excel": _generate_visit_graph_from_excel,
    }

    try:
        # Construct the system prompt dynamically (or keep it static if preferred)
        today_date = datetime.date.today().isoformat()
        # Double the curly braces for literal output in f-string
        system_prompt = f"""You are HospiSys AI, a helpful assistant for '{current_user.username}' (Role: '{current_user.role}') at this hospital management system. Today's date is {today_date}. You have access to two types of data sources via tools: a patient Database (DB) for specific history and an Excel Visit Log (Excel) for aggregate/recent activity.

        **IMPORTANT: Use the RIGHT tool for the job!**

        **DATABASE Tools (Use for SPECIFIC patient details & history):**
        *   `_find_patient(identifier_or_name: str)`: [DB] Finds ONE patient by ID or name. Returns basic info `{{'patient_id', 'patient_identifier', 'name', 'dob'}}` or 'not found'. **ALWAYS use this first if the query mentions a specific patient.** Get the `patient_identifier` from the result to use in other DB tools.
        *   `_get_patient_recent_visits(patient_identifier: str, limit: int = 5)`: [DB] Gets recent detailed visits (reason, recorder) for a *specific* patient identifier. Requires `patient_identifier` from `_find_patient`.
        *   `_get_patient_prescriptions(patient_identifier: str, limit: int = 10)`: [DB] Gets prescriptions for a *specific* patient identifier. Requires `patient_identifier`.
        *   `_get_patient_reports(patient_identifier: str, limit: int = 10)`: [DB] Gets report summaries (type, date, URL) for a *specific* patient identifier. Requires `patient_identifier`.

        **EXCEL LOG Tools (Use for GENERAL activity, counts, recent overview across ALL patients):**
        *   `_get_recent_visits_from_excel(limit: int = 5)`: [Excel] Gets the latest visit entries (PatientID, Name, VisitDateTimeUTC) across *all* patients from the log file. Use for "Who visited recently?".
        *   `_get_visit_counts_from_excel(period: str = 'today')`: [Excel] Counts *total* visits logged in the Excel file for a given period. Valid periods: 'today', 'yesterday', 'last_7_days', 'current_month'. Returns `{{'period': str, 'visit_count': int}}` or error. Use for "How many visits today/yesterday/last 7 days/this month?".
        *   `_generate_visit_graph_from_excel(period: str = 'last_7_days')`: [Excel] Generates a bar chart of daily visit counts from the log file for a period. Valid periods: 'last_7_days', 'last_30_days', 'current_month'. Returns `{{'graph_description': str, 'graph_url': str}}` (URL to the PNG image) or error. Use for "Graph visits for the last week/month". **When successful, tell the user you've generated the graph and provide the URL.**

        **Workflow Guidance:**
        1.  Query about a specific patient (e.g., "history for John Doe", "prescriptions for MRN123")? -> Use `_find_patient` first, then other **DB** tools using the returned `patient_identifier`.
        2.  Query about general recent activity ("Who visited lately?", "Show recent check-ins") -> Use `_get_recent_visits_from_excel`.
        3.  Query about total visit counts ("How many patients today?", "Visit count last 7 days") -> Use `_get_visit_counts_from_excel`.
        4.  Query asking to visualize visit trends ("Graph visits last week", "Chart visits this month") -> Use `_generate_visit_graph_from_excel`. Provide the returned URL to the user.
        5.  Summarize tool results clearly. If a tool returns an error or 'not found', state that accurately.
        6.  Limitations: Stick to information retrieval using the provided tools. **DO NOT provide medical advice, diagnosis, or interpretation of results.** If asked something outside your tool capabilities, state your limitations clearly. Do not hallucinate information not provided by the tools.
        """

        # Start chat session
        chat = model.start_chat(
            enable_automatic_function_calling=False # We will handle the calls manually
        )

        # Send the first message including the system prompt and user query
        initial_message = system_prompt + "\n\n---\nUser Query:\n" + user_query
        logger.info("--- Sending initial query to Gemini ---")
        request_options = {'timeout': 180} # 3 minutes timeout
        response = chat.send_message(
            initial_message,
            generation_config=GenerationConfig(temperature=0.1),
            request_options=request_options
        )
        logger.info("--- Initial Gemini response received ---")

        # Manual Function Calling Loop
        max_turns = 6
        turn = 0
        while turn < max_turns:
            turn += 1
            logger.info(f"--- AI Interaction Turn {turn}/{max_turns} ---")

            # Check for function call
            try:
                part = response.candidates[0].content.parts[0]
                if not hasattr(part, 'function_call') or not part.function_call:
                    logger.info("No function call in response part, proceeding to extract text.")
                    break
                function_call = part.function_call
                function_name = function_call.name
                args = {k: v for k, v in function_call.args.items()}
                logger.info(f"Detected Function Call: {function_name} with args: {args}")
            except (IndexError, AttributeError, ValueError, TypeError) as e:
                logger.warning(f"Could not extract function call (Turn {turn}). Error: {e}. Proceeding to extract text.", exc_info=True)
                break

            # Execute the function
            if function_name not in available_tools:
                logger.error(f"AI requested an unknown function: {function_name}")
                api_response_payload = {'error': f'Function "{function_name}" is not available.'} # Already a dict
            else:
                api_func = available_tools[function_name]
                logger.info(f"Calling function '{function_name}' with args: {args}")
                try:
                    function_result = api_func(**args)
                    api_response_payload = function_result # Keep the original result (dict, list, or str)
                    logger.info(f"Function '{function_name}' executed successfully.")
                except TypeError as te:
                     logger.error(f"Argument mismatch calling function {function_name} with {args}. Error: {te}", exc_info=True)
                     api_response_payload = f'Error calling function {function_name}: Invalid arguments provided. {te}' # Return string error
                except Exception as e:
                    logger.error(f"Error executing function {function_name} with {args}: {e}", exc_info=True)
                    api_response_payload = f'Error executing function {function_name}: {str(e)}' # Return string error

            # --- Send Function Response back to Gemini ---
            # ***** FIX: Ensure payload is always a dictionary *****
            try:
                # Ensure the response payload is always a dict for marshalling to Struct
                final_payload_for_gemini = {}
                if isinstance(api_response_payload, dict):
                    # If it's already a dictionary, use it directly
                    final_payload_for_gemini = api_response_payload
                elif isinstance(api_response_payload, list):
                    # If it's a list (e.g., from get recent visits), wrap it
                    final_payload_for_gemini = {'result': api_response_payload}
                elif isinstance(api_response_payload, str):
                    # If it's a string (error message or simple status), wrap it
                    # Use 'message' or 'error' key based on content? (Optional refinement)
                    if "error" in api_response_payload.lower() or "not found" in api_response_payload.lower() or "invalid" in api_response_payload.lower() or "could not" in api_response_payload.lower() or "failed" in api_response_payload.lower():
                         final_payload_for_gemini = {'error': api_response_payload}
                    else:
                         final_payload_for_gemini = {'message': api_response_payload}
                else:
                    # For any other unexpected type, convert to string and wrap
                    logger.warning(f"Function {function_name} returned unexpected type {type(api_response_payload)}. Converting to string.")
                    final_payload_for_gemini = {'message': str(api_response_payload)}

                logger.debug(f"Prepared payload for Gemini FunctionResponse ({function_name}): {final_payload_for_gemini}")

                function_response_part = glm.Part(
                    function_response=glm.FunctionResponse(
                        name=function_name,
                        response=final_payload_for_gemini # Use the guaranteed dictionary payload
                    )
                )

                logger.info(f"Sending function response for '{function_name}' back to Gemini.")
                response = chat.send_message(
                    glm.Content(parts=[function_response_part]),
                    request_options=request_options
                )
                logger.info(f"--- Gemini response received after function call {function_name} ---")

            except Exception as send_err:
                 logger.error(f"Error sending function response for {function_name} back to Gemini: {send_err}", exc_info=True)
                 # Return the specific error encountered during the send operation
                 return jsonify({'error': f'Error communicating function ({function_name}) result back to AI: {send_err}'}), 500
            # ***** END OF FIX *****

        # End Loop
        if turn >= max_turns:
            logger.warning(f"AI interaction reached max turns ({max_turns}). Returning last response.")

        # --- Extract Final Answer ---
        ai_answer = "Error: Could not extract final answer from AI response." # Default error
        logger_suffix = ""
        try:
            # Check for blocking first
            if hasattr(response, 'prompt_feedback') and response.prompt_feedback.block_reason:
                block_reason = response.prompt_feedback.block_reason
                block_message = getattr(block_reason, 'name', str(block_reason))
                ai_answer = f"AI Error: Request blocked due to safety settings ({block_message}). Please rephrase your query."
                logger.warning(f"AI request blocked by safety settings. Reason: {block_message}")
            # Check candidates and parts for text
            elif response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
                 # Combine text from all parts
                 final_text_parts = [part.text for part in response.candidates[0].content.parts if hasattr(part, 'text')]
                 ai_answer = "".join(final_text_parts).strip()

                 if not ai_answer:
                    # Check if the last part was maybe a function call that didn't lead to text
                    last_part = response.candidates[0].content.parts[-1]
                    if hasattr(last_part, 'function_call'):
                        ai_answer = f"I performed an action ({last_part.function_call.name}) but didn't generate a text summary. Was there something specific you wanted to know about the result?"
                        logger.warning("AI response ended with a function call, no final text summary found.")
                    else:
                        ai_answer = "I processed the request but couldn't generate a final text response."
                        logger.warning("AI response has parts but no text content extracted.")
                 else:
                     logger.info("--- Final AI text response extracted successfully ---")

            else:
                 # Fallback if structure is unexpected
                 ai_answer = "Sorry, I received an unexpected response format from the AI."
                 logger.warning("AI response structure unexpected. No candidates or parts found.")

        except Exception as extract_err:
             logger.error(f"Error extracting final AI answer: {extract_err}", exc_info=True)
             ai_answer = "Sorry, there was an internal error processing the AI's final response."

        # Log final answer snippet
        logger.info(f"--- AI Final Response to User {current_user.username} ---")
        log_snippet = ai_answer[:200].replace('\n', ' ') # Log first 200 chars, replace newlines for cleaner log
        if len(ai_answer) > 200 : logger_suffix = "..."
        logger.info(f"Final AI Answer Snippet: '{log_snippet}{logger_suffix}'")

        return jsonify({'answer': ai_answer})

    except genai.types.generation_types.BlockedPromptException as bpe:
        logger.error(f"AI Error: Prompt blocked for User {current_user.username}. Query: '{user_query[:100]}...'. Error: {bpe}", exc_info=True)
        return jsonify({'error': f'AI request blocked due to safety settings. Please revise your query.'}), 400
    except Exception as e:
        # Catch the specific ValueError if it somehow still occurs
        if isinstance(e, ValueError) and 'Invalid format specifier' in str(e):
            logger.error(f"FATAL: F-string formatting error in system_prompt still present! Error: {e}", exc_info=True)
            return jsonify({'error': 'Internal server error: AI prompt configuration issue.'}), 500
        # Handle other unexpected errors
        logger.error(f"Unhandled error during AI interaction for User {current_user.username}: {e}", exc_info=True)
        return jsonify({'error': 'An unexpected error occurred while communicating with the AI assistant.'}), 500


# --- Utility / Initialization ---

def create_default_users():
    """Creates default user accounts if they don't exist."""
    # Ensure this runs within an app context
    with app.app_context():
        default_users_data = [
            ("superadmin", "superadmin123", "superadmin"),
            ("doctor", "doctor123", "doctor"),
            ("receptionist", "receptionist123", "receptionist"),
            ("pharmacist", "pharmacist123", "pharmacist"),
            ("labtechnician", "labtech123", "labtechnician")
        ]
        created_count = 0
        logger.info("Checking or creating default users...")
        for username, password, role in default_users_data:
            try:
                # Check if user with this username AND role exists
                existing_user = User.query.filter_by(username=username, role=role).first()
                if not existing_user:
                    user = User(username=username, role=role)
                    user.set_password(password) # Hash the password
                    db.session.add(user)
                    logger.info(f"Creating default user: {username} (Role: {role})")
                    created_count += 1
                # else: logger.debug(f"Default user {username} ({role}) already exists.")
            except Exception as e:
                # Log error and rollback immediately if one user fails
                logger.error(f"Error checking/creating default user {username} ({role}): {e}", exc_info=True)
                db.session.rollback()
                return # Stop trying if one fails

        # Commit all newly created users together
        if created_count > 0:
            try:
                db.session.commit()
                logger.info(f"Successfully committed {created_count} new default users.")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to commit newly created default users: {e}", exc_info=True)
        else:
            logger.info("No new default users needed.")

def initialize_app(current_app):
     """Perform initial setup tasks."""
     with current_app.app_context():
        logger.info("Application context entered for initialization.")
        try:
            # Create database tables if they don't exist (safe for SQLite, less critical for others if using migrations)
            # db.create_all() should ideally be managed by Flask-Migrate (flask db init, migrate, upgrade)
            # but can be useful for initial setup or simple SQLite cases.
            # Check if DB file exists, if not, assume tables need creation.
            db_path_str = str(current_app.config['SQLALCHEMY_DATABASE_URI']) # Ensure it's a string
            if db_path_str.startswith('sqlite:///'):
                 # Construct absolute path if it's relative
                 db_file_rel = db_path_str[len('sqlite:///'):]
                 if not os.path.isabs(db_file_rel):
                     db_file = os.path.join(current_app.instance_path, db_file_rel)
                 else:
                     db_file = db_file_rel

                 db_dir = os.path.dirname(db_file)
                 if not os.path.exists(db_dir):
                     try:
                         os.makedirs(db_dir)
                         logger.info(f"Created directory for database: {db_dir}")
                     except OSError as dir_err:
                         logger.error(f"Error creating database directory {db_dir}: {dir_err}", exc_info=True)

                 if not os.path.exists(db_file):
                    logger.info(f"Database file not found at {db_file}, attempting to create tables...")
                    try:
                         db.create_all()
                         logger.info("Database tables created (or already existed).")
                    except Exception as create_err:
                         logger.error(f"Error creating database tables: {create_err}", exc_info=True)


            # Create default users (idempotent check inside)
            create_default_users()
            logger.info("Default user check complete.")

            # Ensure essential directories exist
            upload_folder = current_app.config['UPLOAD_FOLDER']
            if not os.path.exists(upload_folder):
                try:
                    os.makedirs(upload_folder)
                    logger.info(f"Created upload folder: {upload_folder}")
                except OSError as e:
                    logger.error(f"Error creating upload folder {upload_folder}: {e}")

            excel_log_dir = os.path.dirname(EXCEL_FILE_PATH)
            if not os.path.exists(excel_log_dir):
                 try:
                    os.makedirs(excel_log_dir)
                    logger.info(f"Created Excel log directory: {excel_log_dir}")
                 except OSError as e:
                     logger.error(f"Error creating Excel log directory {excel_log_dir}: {e}")


        except Exception as e:
            logger.error(f"Error during application initialization: {e}", exc_info=True)
        logger.info("Application initialization actions complete.")

# Call initialization explicitly before running
initialize_app(app)

if __name__ == '__main__':
    # Use environment variable for debug mode, default to False (production)
    is_debug = os.getenv('FLASK_DEBUG', 'false').lower() in ['true', '1']
    logger.info(f"Starting Flask application (Debug Mode: {is_debug})...")
    # Port from environment or default to 5000
    port = int(os.getenv('PORT', 5000))
    # Use host='0.0.0.0' to be accessible on network (e.g., in Docker or VMs)
    # Use '127.0.0.1' (default) for local access only
    app_host = os.getenv('FLASK_RUN_HOST', '0.0.0.0')
    logger.info(f"Application will be served on http://{app_host}:{port}")
    # `debug=is_debug` enables Werkzeug debugger and reloader if True
    # `use_reloader=False` might be needed if causing issues with background tasks or multiple workers
    app.run(host=app_host, port=port, debug=is_debug)

# --- END OF FILE app.py ---