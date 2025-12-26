from flask import Flask, jsonify, request, render_template, session, g, send_from_directory
from flask_cors import CORS
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import sqlite3
import secrets
import json
import re
import os
import io
from datetime import datetime, timezone, timedelta
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)
app.secret_key = secrets.token_hex(32)

DATABASE = 'admin_system.db'

valid_tokens = {}

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'anubha@gmail.com').lower()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Anubha@#46')
ADMIN_PIN = os.environ.get('ADMIN_PIN', '468101')
ADMIN_OTP = os.environ.get('ADMIN_OTP', '654321')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads', 'profiles')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Drop existing tables if they exist
    cursor.execute("DROP TABLE IF EXISTS documents")
    cursor.execute("DROP TABLE IF EXISTS document_versions")
    cursor.execute("DROP TABLE IF EXISTS document_comments")
    cursor.execute("DROP TABLE IF EXISTS comments")
    cursor.execute("DROP TABLE IF EXISTS tasks")
    cursor.execute("DROP TABLE IF EXISTS milestones")
    cursor.execute("DROP TABLE IF EXISTS project_assignments")
    cursor.execute("DROP TABLE IF EXISTS projects")
    cursor.execute("DROP TABLE IF EXISTS user_permissions")
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS usertypes")
    cursor.execute("DROP TABLE IF EXISTS activities")
    cursor.execute("DROP TABLE IF EXISTS progress_history")
    cursor.execute("DROP TABLE IF EXISTS user_skills")

    cursor.execute('''
        CREATE TABLE usertypes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_role TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            user_type_id INTEGER NOT NULL,
            phone TEXT,
            department TEXT,
            bio TEXT,
            avatar_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_type_id) REFERENCES usertypes(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE user_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            module TEXT NOT NULL,
            action TEXT NOT NULL,
            granted BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, module, action)
        )
    ''')

    cursor.execute('''CREATE TABLE projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'In Progress',
        progress INTEGER DEFAULT 0,
        deadline DATE,
        reporting_time TIME DEFAULT '09:00',
        created_by_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        FOREIGN KEY (created_by_id) REFERENCES users(id)
    )''')

    cursor.execute('''CREATE TABLE tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'Pending',
        priority TEXT DEFAULT 'Medium',
        deadline DATE,
        project_id INTEGER NOT NULL,
        created_by_id INTEGER NOT NULL,
        assigned_to_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        approval_status TEXT DEFAULT 'pending',
        weightage INTEGER DEFAULT 1,
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (created_by_id) REFERENCES users(id),
        FOREIGN KEY (assigned_to_id) REFERENCES users(id)
    )''')

    cursor.execute('''CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        author_id INTEGER NOT NULL,
        project_id INTEGER,
        task_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users(id),
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (task_id) REFERENCES tasks(id)
    )''')

    cursor.execute('''CREATE TABLE documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_size INTEGER,
        uploaded_by_id INTEGER NOT NULL,
        project_id INTEGER,
        task_id INTEGER,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (uploaded_by_id) REFERENCES users(id),
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (task_id) REFERENCES tasks(id)
    )''')

    cursor.execute('''CREATE TABLE milestones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        due_date DATE,
        status TEXT DEFAULT 'Pending',
        project_id INTEGER NOT NULL,
        weightage INTEGER DEFAULT 1,
        created_by_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (created_by_id) REFERENCES users(id)
    )''')

    cursor.execute('''CREATE TABLE project_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (project_id) REFERENCES projects(id),
    UNIQUE(user_id, project_id)
)''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS progress_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        progress_percentage INTEGER,
        tasks_completed INTEGER,
        total_tasks INTEGER,
        milestones_completed INTEGER,
        total_milestones INTEGER,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id)
    )
''')

    cursor.execute('''
    CREATE INDEX IF NOT EXISTS idx_progress_project_date 
    ON progress_history(project_id, recorded_at)
''')

    cursor.execute('''CREATE TABLE activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        activity_type TEXT NOT NULL,
        description TEXT NOT NULL,
        project_id INTEGER,
        task_id INTEGER,
        milestone_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (task_id) REFERENCES tasks(id),
        FOREIGN KEY (milestone_id) REFERENCES milestones(id)
    )''')

    cursor.execute('''CREATE TABLE user_skills (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        skill_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        UNIQUE(user_id, skill_name)
    )''')

    # Insert default user types
    cursor.execute("INSERT INTO usertypes (user_role) VALUES ('Administrator')")
    cursor.execute("INSERT INTO usertypes (user_role) VALUES ('Employee')")

    conn.commit()
    conn.close()
    print("[OK] Database initialized successfully!")


def migrate_db():
    """Add new columns without wiping existing data"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # List of columns to add
    columns_to_add = [
        ('users', 'phone', 'TEXT'),
        ('users', 'department', 'TEXT'),
        ('users', 'bio', 'TEXT'),
        ('users', 'avatar_url', 'TEXT'),
        ('projects', 'completed_at', 'TIMESTAMP'),
        ('projects', 'reporting_time', 'TIME')
    ]

    for table, column, col_type in columns_to_add:
        try:
            cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column} {col_type}')
        except sqlite3.OperationalError:
            pass  # Column already exists

    conn.commit()
    conn.close()
    print("[OK] Database migration completed!")


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def validate_password_complexity(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter."
    special_chars = len(
        re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
    if special_chars < 2:
        return False, "Password must contain at least two special characters."
    return True, "Password is valid."


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if token in valid_tokens:
                g.current_user_id = valid_tokens[token]['user_id']
                g.current_user_type = valid_tokens[token].get('user_type', 'employee')
                return f(*args, **kwargs)
        
        if 'user_id' in session:
            g.current_user_id = session.get('user_id')
            g.current_user_type = session.get('user_type', 'employee')
            return f(*args, **kwargs)

        return jsonify({"error": "Authentication required"}), 401

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        is_admin = False
        
        # Check Bearer token
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if token in valid_tokens and valid_tokens[token].get('user_type') == 'admin':
                is_admin = True
        
        # Check session
        if session.get('user_type') == 'admin' or session.get('admin'):
            is_admin = True
        
        if not is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function


def get_current_user_id():
    return getattr(g, 'current_user_id', None) or session.get('user_id')


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/admin-dashboard")
def admin_dashboard():
    return render_template("admin-dashboard.html")


@app.route("/employee-dashboard")
def employee_dashboard():
    return render_template("employee-dashboard.html")


@app.route("/api/admin/login/step1", methods=["POST"])
def login_step1():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    confirm_password = data.get("confirm_password") or ""
    admin_pin = (data.get("admin_pin") or "").strip()

    if not email or not password or not confirm_password or not admin_pin:
        return jsonify({"error": "All fields are required."}), 400

    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Invalid email format."}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    if not admin_pin.isdigit() or len(admin_pin) != 6:
        return jsonify({"error": "Admin PIN must be exactly 6 digits."}), 400

    if email != ADMIN_EMAIL:
        return jsonify({"error": "Email not found."}), 400

    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Incorrect password."}), 400

    if admin_pin != ADMIN_PIN:
        return jsonify({"error": "Invalid Admin PIN."}), 400

    return jsonify(
        {"message":
         "OTP has been sent to your registered email (simulated)."}), 200


@app.route("/api/admin/login/step2", methods=["POST"])
def login_step2():
    data = request.get_json() or {}
    otp = data.get("otp") or ""

    if not otp:
        return jsonify({"error": "OTP is required."}), 400

    if otp != ADMIN_OTP:
        return jsonify({"error": "Invalid OTP provided."}), 400

    session_token = secrets.token_urlsafe(32)
    session['admin'] = True
    session['admin_token'] = session_token
    session['user_type'] = 'admin'

    valid_tokens[session_token] = {
        'user_id': 0,  # Admin has ID 0
        'username': 'admin',
        'user_type': 'admin',
        'created_at': datetime.now(timezone.utc)
    }

    return jsonify({
        "session_token": session_token,
        "admin_name": "Super Admin",
        "success": True,
        "message": "Login successful"
    }), 200


@app.route("/api/admin/dashboard/overdue-items", methods=["GET"])
@admin_required
def get_overdue_items():
    """Get all overdue items for admin"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Overdue tasks
        cursor.execute('''
            SELECT t.id, t.title, t.description, t.status, t.priority, 
                   t.deadline, t.project_id, p.title as project_name,
                   t.assigned_to_id, u.username as assigned_to_name,
                   t.created_by_id, uc.username as created_by_name,
                   t.created_at, t.approval_status,
                   julianday('now') - julianday(t.deadline) as days_overdue
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            WHERE t.deadline < date('now') 
            AND t.status != 'Completed'
            AND t.status != 'Overdue'
            ORDER BY t.deadline ASC
        ''')
        overdue_tasks = cursor.fetchall()
        
        # Overdue projects
        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name,
                   p.created_at,
                   julianday('now') - julianday(p.deadline) as days_overdue
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            WHERE p.deadline < date('now') 
            AND p.status != 'Completed'
            ORDER BY p.deadline ASC
        ''')
        overdue_projects = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            "overdue_tasks": [dict(row) for row in overdue_tasks],
            "overdue_projects": [dict(row) for row in overdue_projects],
            "total_overdue_tasks": len(overdue_tasks),
            "total_overdue_projects": len(overdue_projects)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/dashboard/completed-outcomes", methods=["GET"])
@admin_required
def get_completed_outcomes():
    """Get all completed projects (outcomes)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name,
                   p.created_at, p.completed_at,
                   COUNT(DISTINCT t.id) as total_tasks,
                   COUNT(DISTINCT CASE WHEN t.status = 'Completed' THEN t.id END) as completed_tasks,
                   COUNT(DISTINCT m.id) as total_milestones,
                   COUNT(DISTINCT CASE WHEN m.status = 'Completed' THEN m.id END) as completed_milestones
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            WHERE p.status = 'Completed'
            GROUP BY p.id
            ORDER BY p.completed_at DESC
        ''')
        
        completed_projects = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in completed_projects]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/dashboard/recent-actions", methods=["GET"])
@admin_required
def get_recent_actions():
    """Get recent actions from all employees"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT a.id, a.activity_type, a.description, a.created_at,
                   u.username, u.email, u.user_type_id, ut.user_role,
                   p.title as project_title, t.title as task_title,
                   m.title as milestone_title,
                   CASE 
                     WHEN a.activity_type = 'project_created' THEN 'fas fa-folder-plus'
                     WHEN a.activity_type = 'task_created' THEN 'fas fa-tasks'
                     WHEN a.activity_type = 'task_completed' THEN 'fas fa-check-circle'
                     WHEN a.activity_type = 'milestone_created' THEN 'fas fa-flag'
                     WHEN a.activity_type = 'milestone_completed' THEN 'fas fa-flag-checkered'
                     WHEN a.activity_type = 'document_uploaded' THEN 'fas fa-file-upload'
                     WHEN a.activity_type = 'document_deleted' THEN 'fas fa-file-times'
                     ELSE 'fas fa-history'
                   END as icon_class
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            LEFT JOIN projects p ON a.project_id = p.id
            LEFT JOIN tasks t ON a.task_id = t.id
            LEFT JOIN milestones m ON a.milestone_id = m.id
            ORDER BY a.created_at DESC
            LIMIT 50
        ''')
        
        activities = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in activities]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/dashboard/activities", methods=["GET"])
@admin_required
def get_admin_activities():
    """Get all activities for admin dashboard"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT a.id, a.activity_type, a.description, a.created_at,
                   u.username, u.email, p.title as project_title,
                   t.title as task_title, m.title as milestone_title
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN projects p ON a.project_id = p.id
            LEFT JOIN tasks t ON a.task_id = t.id
            LEFT JOIN milestones m ON a.milestone_id = m.id
            ORDER BY a.created_at DESC
            LIMIT 100
        ''')
        
        activities = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in activities]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/dashboard/stats", methods=["GET"])
@admin_required
def get_admin_dashboard_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT COUNT(*) as count FROM projects WHERE status = ?',
            ('In Progress', ))
        active_projects = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE status = ?',
                       ('Completed', ))
        completed_tasks = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE status = ?',
                       ('In Progress', ))
        active_tasks = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM tasks 
            WHERE deadline < date('now') AND status != ? AND status != ?
        ''', ('Completed', 'Overdue'))
        overdue_tasks = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM tasks 
            WHERE approval_status = ? OR approval_status IS NULL
        ''', ('pending', ))
        pending_approvals = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM users')
        total_users = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM usertypes')
        total_user_types = cursor.fetchone()['count']

        # Add total outcomes (completed projects)
        cursor.execute('SELECT COUNT(*) as count FROM projects WHERE status = ?',
                       ('Completed', ))
        total_outcomes = cursor.fetchone()['count']

        conn.close()

        return jsonify({
            "active_projects": active_projects,
            "completed_tasks": completed_tasks,
            "active_tasks": active_tasks,
            "overdue_tasks": overdue_tasks,
            "pending_approvals": pending_approvals,
            "total_users": total_users,
            "total_user_types": total_user_types,
            "total_outcomes": total_outcomes
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/projects/<int:project_id>/calculate-progress", methods=["GET"])
@login_required
def calculate_project_progress(project_id):
    """
    Calculate project progress based on: 
    - 70% weight:  Task completion rate
    - 30% weight: Milestone completion rate
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get task progress data
        cursor.execute('''
            SELECT 
                COUNT(*) as total_tasks,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                COALESCE(SUM(weightage), 0) as total_weightage,
                COALESCE(SUM(CASE WHEN status = 'Completed' THEN weightage ELSE 0 END), 0) as completed_weightage
            FROM tasks 
            WHERE project_id = ? 
        ''', (project_id,))
        task_data = cursor.fetchone()
        
        # Get milestone progress data
        cursor.execute('''
            SELECT 
                COUNT(*) as total_milestones,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                COALESCE(SUM(weightage), 0) as total_m_weightage,
                COALESCE(SUM(CASE WHEN status = 'Completed' THEN weightage ELSE 0 END), 0) as completed_m_weightage
            FROM milestones 
            WHERE project_id = ?
        ''', (project_id,))
        milestone_data = cursor.fetchone()
        
        # Calculate weighted progress
        task_progress = 0
        if task_data['total_weightage'] and task_data['total_weightage'] > 0:
            task_progress = (task_data['completed_weightage'] / task_data['total_weightage']) * 100
        
        milestone_progress = 0
        if milestone_data['total_m_weightage'] and milestone_data['total_m_weightage'] > 0:
            milestone_progress = (milestone_data['completed_m_weightage'] / milestone_data['total_m_weightage']) * 100
        
        # Overall progress:  70% tasks + 30% milestones
        overall_progress = int((task_progress * 0.7) + (milestone_progress * 0.3))
        
        # Update project progress in database
        cursor.execute('''
            UPDATE projects 
            SET progress = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (overall_progress, project_id))
        
        # Record progress history
        cursor.execute('''
            INSERT INTO progress_history (
                project_id, progress_percentage, 
                tasks_completed, total_tasks,
                milestones_completed, total_milestones
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            project_id, overall_progress,
            task_data['completed_tasks'] or 0, task_data['total_tasks'] or 0,
            milestone_data['completed_milestones'] or 0, milestone_data['total_milestones'] or 0
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "project_id": project_id,
            "progress":  overall_progress,
            "task_progress": round(task_progress, 2),
            "milestone_progress": round(milestone_progress, 2),
            "tasks_completed": task_data['completed_tasks'] or 0,
            "total_tasks": task_data['total_tasks'] or 0,
            "milestones_completed":  milestone_data['completed_milestones'] or 0,
            "total_milestones": milestone_data['total_milestones'] or 0,
            "message": "Progress calculated successfully"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/projects/<int:project_id>/progress-history", methods=["GET"])
@login_required
def get_project_progress_history(project_id):
    """
    Retrieve historical progress data for charts/graphs
    """
    try: 
        conn = get_db_connection()
        cursor = conn. cursor()
        
        cursor.execute('''
            SELECT 
                progress_percentage,
                tasks_completed,
                total_tasks,
                milestones_completed,
                total_milestones,
                recorded_at
            FROM progress_history 
            WHERE project_id = ? 
            ORDER BY recorded_at DESC
            LIMIT 30
        ''', (project_id,))
        
        history = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in history]), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/dashboard/live-progress", methods=["GET"])
@login_required
def get_live_dashboard_progress():
    """
    Get real-time progress for all active projects
    Differentiates between admin and employee views
    """
    try:
        user_id = get_current_user_id()
        is_admin = session.get('admin') or session.get('user_type') == 'admin'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if is_admin:
            # Admin sees all active projects
            cursor.execute('''
                SELECT 
                    p.id,
                    p. title,
                    p.description,
                    p.status,
                    p.progress,
                    p.deadline,
                    p.reporting_time,
                    p.created_at,
                    p.updated_at,
                    u.username as creator_name,
                    COUNT(DISTINCT t.id) as total_tasks,
                    SUM(CASE WHEN t. status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                    COUNT(DISTINCT m.id) as total_milestones,
                    SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                    COUNT(DISTINCT pa.user_id) as team_size
                FROM projects p
                LEFT JOIN users u ON p.created_by_id = u.id
                LEFT JOIN tasks t ON p.id = t.project_id
                LEFT JOIN milestones m ON p. id = m.project_id
                LEFT JOIN project_assignments pa ON p.id = pa.project_id
                WHERE p.status != 'Completed'
                GROUP BY p.id
                ORDER BY p.updated_at DESC
            ''')
        else:
            # Employees see only assigned projects
            cursor.execute('''
                SELECT DISTINCT
                    p.id,
                    p.title,
                    p.description,
                    p.status,
                    p. progress,
                    p.deadline,
                    p.reporting_time,
                    p.created_at,
                    p. updated_at,
                    u.username as creator_name,
                    COUNT(DISTINCT t. id) as total_tasks,
                    SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                    COUNT(DISTINCT m.id) as total_milestones,
                    SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                    COUNT(DISTINCT pa.user_id) as team_size
                FROM projects p
                LEFT JOIN users u ON p.created_by_id = u.id
                LEFT JOIN tasks t ON p.id = t. project_id
                LEFT JOIN milestones m ON p.id = m.project_id
                LEFT JOIN project_assignments pa ON p. id = pa.project_id
                WHERE (p.created_by_id = ? OR p.id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ? 
                ))
                AND p.status != 'Completed'
                GROUP BY p.id
                ORDER BY p.updated_at DESC
            ''', (user_id, user_id))
        
        projects = cursor.fetchall()
        conn.close()
        
        formatted_projects = []
        for project in projects:
            project_dict = dict(project)
            
            # Calculate additional metrics
            try:
                created_at = datetime.strptime(project_dict['created_at'], '%Y-%m-%d %H:%M:%S')
            except:
                created_at = datetime.now()
            
            now = datetime.now()
            days_active = max(1, (now - created_at).days)
            progress_per_day = project_dict['progress'] / days_active if days_active > 0 else 0
            
            # Estimate completion date
            estimated_completion_str = None
            if project_dict['progress'] > 0 and progress_per_day > 0:
                days_remaining = (100 - project_dict['progress']) / progress_per_day
                estimated_completion = now + timedelta(days=days_remaining)
                estimated_completion_str = estimated_completion.strftime('%Y-%m-%d')
            
            # Calculate sub-progress metrics
            tasks_progress = int((project_dict['completed_tasks'] / project_dict['total_tasks'] * 100)) if project_dict['total_tasks'] > 0 else 0
            milestones_progress = int((project_dict['completed_milestones'] / project_dict['total_milestones'] * 100)) if project_dict['total_milestones'] > 0 else 0
            
            # Health status
            health_status = 'good' if project_dict['progress'] >= 70 else 'warning' if project_dict['progress'] >= 40 else 'danger'
            
            project_dict. update({
                'days_active': days_active,
                'progress_per_day':  round(progress_per_day, 2),
                'estimated_completion': estimated_completion_str,
                'tasks_progress': tasks_progress,
                'milestones_progress': milestones_progress,
                'health_status':  health_status
            })
            
            formatted_projects.append(project_dict)
        
        # Calculate average progress
        avg_progress = 0
        if formatted_projects: 
            avg_progress = round(sum(p['progress'] for p in formatted_projects) / len(formatted_projects), 2)
        
        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "total_projects":  len(formatted_projects),
            "average_progress": avg_progress,
            "projects": formatted_projects
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/users/<int:user_id>/permissions", methods=["GET"])
@admin_required
def get_user_permissions(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (user_id, ))
        permissions = cursor.fetchall()
        conn.close()

        result = {}
        for perm in permissions:
            module = perm['module']
            if module not in result:
                result[module] = {}
            result[module][perm['action']] = bool(perm['granted'])

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:user_id>/permissions", methods=["POST"])
@admin_required
def set_user_permissions(user_id):
    try:
        data = request.get_json() or {}
        permissions_data = data.get("permissions")

        if isinstance(permissions_data, str):
            permissions = json.loads(permissions_data)
        else:
            permissions = permissions_data or {}

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM user_permissions WHERE user_id = ?',
                       (user_id, ))

        for module, actions in permissions.items():
            if isinstance(actions, dict):
                for action, granted in actions.items():
                    cursor.execute(
                        '''
                        INSERT INTO user_permissions (user_id, module, action, granted)
                        VALUES (?, ?, ?, ?)
                    ''', (user_id, module, action, 1 if granted else 0))

        conn.commit()
        conn.close()

        return jsonify({"message": "Permissions updated successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/usertypes", methods=["GET"])
@login_required
def get_user_types():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, user_role, created_at FROM usertypes ORDER BY user_role'
        )
        user_types = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in user_types]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/usertypes", methods=["POST"])
@admin_required
def create_user_type():
    try:
        data = request.get_json() or {}
        user_role = (data.get("user_role") or "").strip()

        if not user_role:
            return jsonify({"error": "User role is required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('INSERT INTO usertypes (user_role) VALUES (?)',
                           (user_role, ))
            conn.commit()
            user_type_id = cursor.lastrowid
            conn.close()

            return jsonify({
                "id": user_type_id,
                "user_role": user_role,
                "message": "User type created successfully!"
            }), 201

        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "User role already exists."}), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/usertypes/<int:id>", methods=["PUT"])
@admin_required
def update_user_type(id):
    try:
        data = request.get_json() or {}
        user_role = (data.get("user_role") or "").strip()

        if not user_role:
            return jsonify({"error": "User role is required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?', (id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User type not found."}), 404

        try:
            cursor.execute('UPDATE usertypes SET user_role = ? WHERE id = ?',
                           (user_role, id))
            conn.commit()
            conn.close()

            return jsonify({
                "id": id,
                "user_role": user_role,
                "message": "User type updated successfully!"
            }), 200

        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "User role already exists."}), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/usertypes/<int:id>", methods=["DELETE"])
@admin_required
def delete_user_type(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?', (id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User type not found."}), 404

        cursor.execute(
            'SELECT COUNT(*) as count FROM users WHERE user_type_id = ?',
            (id, ))
        if cursor.fetchone()['count'] > 0:
            conn.close()
            return jsonify({
                "error":
                "Cannot delete user type that has associated users."
            }), 400

        cursor.execute('DELETE FROM usertypes WHERE id = ?', (id, ))
        conn.commit()
        conn.close()

        return jsonify({"message": "User type deleted successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["GET"])
@login_required
def get_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role, u.created_at
            FROM users u 
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id 
            ORDER BY u.created_at DESC
        ''')
        users = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in users]), 200
    except Exception as e:
        print(f"[ERROR] /api/users GET failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
@admin_required
def create_user():
    try:
        data = request.get_json()
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        confirm_password = data.get("confirm_password") or ""
        user_type_id = data.get("user_type_id")
        permissions_data = data.get("permissions")

        if isinstance(permissions_data, str):
            try:
                permissions = json.loads(permissions_data)
            except json.JSONDecodeError:
                permissions = {}
        else:
            permissions = permissions_data or {}

        if not all([username, email, password, confirm_password, user_type_id
                    ]):
            return jsonify({"error":
                            "All mandatory fields are required."}), 400

        if len(username) < 3:
            return jsonify(
                {"error": "Username must be at least 3 characters."}), 400

        if "@" not in email or "." not in email.split("@")[-1]:
            return jsonify({"error": "Invalid email format."}), 400

        is_valid, validation_message = validate_password_complexity(password)
        if not is_valid:
            return jsonify({"error": validation_message}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?',
                       (user_type_id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Invalid user type selected."}), 400

        try:
            hashed_password = generate_password_hash(password,
                                                     method='pbkdf2:sha256')
            cursor.execute(
                '''
                INSERT INTO users (username, email, password, user_type_id) 
                VALUES (?, ?, ?, ?)
            ''', (username, email, hashed_password, user_type_id))
            conn.commit()

            user_id = cursor.lastrowid

            for module, actions in permissions.items():
                if isinstance(actions, dict):
                    for action, granted in actions.items():
                        try:
                            cursor.execute(
                                '''
                                INSERT INTO user_permissions (user_id, module, action, granted)
                                VALUES (?, ?, ?, ?)
                            ''', (user_id, module, action, 1 if granted else 0))
                        except sqlite3.IntegrityError:
                            pass

            conn.commit()
            conn.close()

            return jsonify({
                "id": user_id,
                "username": username,
                "email": email,
                "user_type_id": user_type_id,
                "permissions": permissions,
                "created_at": datetime.now().isoformat(),
                "message": "User created successfully!"
            }), 201

        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "Username or email already exists."}), 409

    except Exception as e:
        print(f"[ERROR] /api/users POST failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:id>", methods=["GET"])
@admin_required
def get_user(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role, u.created_at
            FROM users u 
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE u.id = ?
        ''', (id, ))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({"error": "User not found."}), 404

        cursor.execute(
            '''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (id, ))
        permissions_rows = cursor.fetchall()
        conn.close()

        permissions = {}
        for perm in permissions_rows:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])

        user_dict = dict(user)
        user_dict['permissions'] = permissions

        return jsonify(user_dict), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:id>", methods=["PUT"])
@admin_required
def update_user(id):
    try:
        data = request.get_json() or {}
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password")
        user_type_id = data.get("user_type_id")
        permissions_data = data.get("permissions")

        if isinstance(permissions_data, str):
            try:
                permissions = json.loads(permissions_data)
            except json.JSONDecodeError:
                permissions = {}
        else:
            permissions = permissions_data or {}

        if not username or not email or not user_type_id:
            return jsonify(
                {"error": "Username, email, and user type are required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM users WHERE id = ?', (id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User not found."}), 404

        try:
            if password:
                is_valid, validation_message = validate_password_complexity(
                    password)
                if not is_valid:
                    conn.close()
                    return jsonify({"error": validation_message}), 400
                hashed_password = generate_password_hash(
                    password, method='pbkdf2:sha256')
                cursor.execute(
                    '''
                    UPDATE users SET username = ?, email = ?, password = ?, user_type_id = ?
                    WHERE id = ?
                ''', (username, email, hashed_password, user_type_id, id))
            else:
                cursor.execute(
                    '''
                    UPDATE users SET username = ?, email = ?, user_type_id = ?
                    WHERE id = ?
                ''', (username, email, user_type_id, id))

            cursor.execute('DELETE FROM user_permissions WHERE user_id = ?',
                           (id, ))

            for module, actions in permissions.items():
                if isinstance(actions, dict):
                    for action, granted in actions.items():
                        try:
                            cursor.execute(
                                '''
                                INSERT INTO user_permissions (user_id, module, action, granted)
                                VALUES (?, ?, ?, ?)
                            ''', (id, module, action, 1 if granted else 0))
                        except sqlite3.IntegrityError:
                            pass

            conn.commit()
            conn.close()

            return jsonify({
                "id": id,
                "username": username,
                "email": email,
                "user_type_id": user_type_id,
                "permissions": permissions,
                "message": "User updated successfully!"
            }), 200

        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "Username or email already exists."}), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:id>", methods=["DELETE"])
@admin_required
def delete_user(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM users WHERE id = ?', (id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User not found."}), 404

        cursor.execute('DELETE FROM user_permissions WHERE user_id = ?',
                       (id, ))
        cursor.execute('DELETE FROM users WHERE id = ?', (id, ))
        conn.commit()
        conn.close()

        return jsonify({"message": "User deleted successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/user/login", methods=["POST"])
def user_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, u.password, ut.user_role
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.email = ?
        ''', (email, ))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({"error": "Invalid email or password."}), 401

        if not check_password_hash(user['password'], password):
            conn.close()
            return jsonify({"error": "Invalid email or password."}), 401

        cursor.execute(
            '''
            SELECT module, action, granted FROM user_permissions
            WHERE user_id = ? ORDER BY module, action
        ''', (user['id'], ))
        permissions_rows = cursor.fetchall()
        conn.close()

        permissions = {}
        for perm in permissions_rows:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])

        # Store authentication info in session
        session['user_id'] = user['id']
        session['user_type'] = 'employee'
        session['username'] = user['username']
        session['permissions'] = permissions
        session['authenticated'] = True

        auth_token = secrets.token_urlsafe(32)
        # Store token in both session and global dict for API authentication
        session['auth_token'] = auth_token
        valid_tokens[auth_token] = {
            'user_id': user['id'],
            'username': user['username'],
            'user_type': 'employee',
            'created_at': datetime.now(timezone.utc)
        }

        return jsonify({
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "user_role": user['user_role'],
            "permissions": permissions,
            "token": auth_token,
            "message": "Login successful!"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/user/logout", methods=["POST"])
def user_logout():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        if token in valid_tokens:
            del valid_tokens[token]
    # Clear session data
    session.clear()
    return jsonify({"message": "Logout successful!"}), 200


@app.route("/api/employee/projects", methods=["GET"])
@login_required
def get_employee_projects():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT DISTINCT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name, p.created_at
            FROM projects p 
            LEFT JOIN users u ON p.created_by_id = u.id
            WHERE p.created_by_id = ? OR p.id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
            ORDER BY p.created_at DESC
        ''', (user_id, user_id))

        projects = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in projects]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/projects", methods=["POST"])
@login_required
def create_employee_project():
    try:
        data = request.get_json() or {}
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        deadline = data.get("deadline")
        reporting_time = data.get("reporting_time", "09:00")
        team_members = data.get("team_members") or []

        if not title:
            return jsonify({"error": "Project title is required"}), 400

        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'Proj', 'Add'))
        perm = cursor.fetchone()

        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied"}), 403

        cursor.execute(
            '''
            INSERT INTO projects (title, description, deadline, reporting_time, created_by_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (title, description, deadline or None, reporting_time, user_id))

        project_id = cursor.lastrowid

        for member_id in team_members:
            try:
                cursor.execute(
                    '''
                    INSERT INTO project_assignments (user_id, project_id)
                    VALUES (?, ?)
                ''', (member_id, project_id))
            except sqlite3.IntegrityError:
                pass

        conn.commit()
        conn.close()

        log_activity(user_id,
                     'project_created',
                     f'Created project: {title} with reporting time {reporting_time}',
                     project_id=project_id)

        # Calculate initial progress
        try:
            calculate_project_progress(project_id)
        except:
            pass

        return jsonify({
            "id": project_id,
            "title": title,
            "message": "Project created successfully!",
            "reporting_time": reporting_time
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/tasks", methods=["GET"])
@login_required
def get_employee_tasks():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT t.id, t.title, t.description, t.status, t.priority, t.deadline,
                   t.project_id, p.title as project_name, t.assigned_to_id,
                   u.username as assigned_to_name, t.created_at, t.approval_status
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            WHERE t.assigned_to_id = ? OR t.created_by_id = ?
            ORDER BY t.created_at DESC
        ''', (user_id, user_id))

        tasks = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in tasks]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/tasks", methods=["POST"])
@login_required
def create_employee_task():
    try:
        data = request.get_json() or {}
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        project_id = data.get("project_id")
        assigned_to_id = data.get("assigned_to_id")
        priority = data.get("priority") or "Medium"
        deadline = data.get("deadline")

        if not title or not project_id:
            return jsonify({"error": "Title and project are required"}), 400

        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check permission
        cursor.execute(
            '''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
            ''', (user_id, 'task', 'Add'))
        perm = cursor.fetchone()

        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied"}), 403

        # Decide status based on whether assigned at creation
        status_to_set = 'Pending'
        if assigned_to_id:
            # Task was assigned immediately — treat as active
            status_to_set = 'In Progress'

        cursor.execute(
            '''
            INSERT INTO tasks (title, description, project_id, created_by_id, assigned_to_id, priority, deadline, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (title, description, project_id, user_id, assigned_to_id, priority, deadline or None, status_to_set)
        )

        conn.commit()
        task_id = cursor.lastrowid
        conn.close()

        # Log activity
        log_activity(user_id,
                     'task_created',
                     f'Created task: {title}',
                     project_id=project_id,
                     task_id=task_id)

        # Update project progress after adding the task
        try:
            calculate_project_progress(project_id)
        except Exception:
            # don't crash on progress calc errors
            pass

        return jsonify({
            "id": task_id,
            "title": title,
            "message": "Task created successfully!"
        }), 201
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/tasks/<int:task_id>/complete", methods=["POST"])
@login_required
def complete_employee_task(task_id):
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get task and project details
        cursor.execute('''
            SELECT status, project_id FROM tasks WHERE id = ?  AND (assigned_to_id = ? OR created_by_id = ?)
        ''', (task_id, user_id, user_id))
        task = cursor.fetchone()

        if not task:
            conn.close()
            return jsonify({"error": "Task not found or permission denied"}), 404

        if task['status'] == 'Completed': 
            conn.close()
            return jsonify({"message": "Task is already completed. "}), 200

        # Update task status
        cursor.execute('''
            UPDATE tasks SET status = ?, completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', ('Completed', task_id))

        conn.commit()
        conn.close()

        # Log activity
        log_activity(user_id, 'task_completed', f'Completed task ID: {task_id}', task_id=task_id)

        # ⭐ IMPORTANT:  Recalculate project progress
        try:
            progress_response = calculate_project_progress(task['project_id'])
            if progress_response[1] == 200:
                progress_data = progress_response[0]. get_json()
                return jsonify({
                    "message": "Task completed successfully! ",
                    "project_progress": progress_data
                }), 200
        except Exception as progress_error:
            print(f"[WARNING] Progress calculation failed: {progress_error}")
            # Don't fail the task completion if progress calc fails
            return jsonify({"message": "Task completed successfully! "}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/milestones", methods=["GET"])
@login_required
def get_employee_milestones():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT m.id, m.title, m.description, m.status, m.due_date, m.project_id,
                   p.title as project_title, m.created_at
            FROM milestones m
            LEFT JOIN projects p ON m.project_id = p.id
            WHERE p.created_by_id = ? OR m.project_id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
            ORDER BY m.created_at DESC
        ''', (user_id, user_id))

        milestones = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in milestones]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/milestones", methods=["POST"])
@login_required
def create_employee_milestone():
    """Create a new milestone for a project with validation"""
    try:
        data = request.get_json() or {}
        title = data.get("title", "").strip()
        description = data.get("description", "").strip()
        project_id = data.get("project_id")
        due_date = data.get("due_date")

        if not title or not project_id:
            return jsonify({"error": "Title and project_id are required"}), 400

        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify user has access to this project
        cursor.execute('''
            SELECT id FROM projects 
            WHERE id = ? AND (
                created_by_id = ? OR id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                )
            )
        ''', (project_id, user_id, user_id))
        
        project = cursor.fetchone()
        if not project:
            conn.close()
            return jsonify({"error": "Project not found or access denied"}), 404

        try:
            cursor.execute('''
                INSERT INTO milestones (title, description, project_id, due_date, status, created_by_id)
                VALUES (?, ?, ?, ?, 'Pending', ?)
            ''', (title, description, project_id, due_date, user_id))

            conn.commit()
            milestone_id = cursor.lastrowid
        except sqlite3.OperationalError as e:
            conn.close()
            print(f"[ERROR] Database schema error: {str(e)}")
            return jsonify({"error": "Database configuration error. Please contact administrator."}), 500

        conn.close()

        log_activity(user_id, 'milestone_created', 
                    f'Created milestone: {title}',
                    project_id=project_id, milestone_id=milestone_id)

        return jsonify({
            "id": milestone_id,
            "title": title,
            "message": "Milestone created successfully!"
        }), 201
    except Exception as e:
        print(f"[ERROR] Milestone creation failed: {str(e)}")
        return jsonify({"error": f"Milestone creation failed: {str(e)}"}), 500


@app.route("/api/employee/milestones/<int:milestone_id>/complete",methods=["POST"])
@login_required
def complete_employee_milestone(milestone_id):
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT project_id FROM milestones WHERE id = ?', (milestone_id,))
        milestone = cursor.fetchone()
        
        if not milestone:
            conn.close()
            return jsonify({"error": "Milestone not found"}), 404

        cursor.execute(
            '''
            UPDATE milestones SET status = ?
            WHERE id = ?
        ''', ('Completed', milestone_id))

        conn.commit()
        conn.close()

        log_activity(user_id,
                     'milestone_completed',
                     f'Completed milestone ID: {milestone_id}',
                     milestone_id=milestone_id)

        # Update project progress
        try:
            calculate_project_progress(milestone['project_id'])
        except:
            pass

        return jsonify({"message": "Milestone completed successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents", methods=["GET"])
@login_required
def get_employee_documents():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT d.id, d.filename, d.original_filename, d.file_size,
                   d.uploaded_by_id, u.username as uploaded_by, d.project_id, d.task_id,
                   d.uploaded_at
            FROM documents d
            LEFT JOIN users u ON d.uploaded_by_id = u.id
            WHERE d.uploaded_by_id = ? OR d.project_id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
            ORDER BY d.uploaded_at DESC
        ''', (user_id, user_id))

        documents = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in documents]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents/upload", methods=["POST"])
@login_required
def upload_employee_document():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        project_id = request.form.get('project_id')

        if not file.filename or not project_id:
            return jsonify({"error": "File and project ID are required"}), 400

        user_id = get_current_user_id()

        # Ensure upload folder exists
        upload_dir = os.path.join('uploads', 'documents')
        os.makedirs(upload_dir, exist_ok=True)

        # Use a secure and unique filename
        filename = f"{secrets.token_hex(8)}_{secure_filename(file.filename)}"
        file_path = os.path.join(upload_dir, filename)
        
        # Save the file
        file.save(file_path)

        file_size = os.path.getsize(file_path)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            INSERT INTO documents (filename, original_filename, file_size, uploaded_by_id, project_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, file.filename, file_size, user_id, project_id))

        conn.commit()
        doc_id = cursor.lastrowid
        conn.close()

        log_activity(user_id,
                     'document_uploaded',
                     f'Uploaded document: {file.filename}',
                     project_id=project_id)

        return jsonify({
            "id": doc_id,
            "filename": file.filename,
            "message": "Document uploaded successfully!"
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents/<int:doc_id>/delete", methods=["DELETE"])
@login_required
def delete_employee_document(doc_id):
    try:
        user_id = get_current_user_id()

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT uploaded_by_id, project_id, filename FROM documents WHERE id = ?',
            (doc_id, ))
        doc_info = cursor.fetchone()

        if not doc_info:
            conn.close()
            return jsonify({"error": "Document not found."}), 404

        # Check ownership or project assignment
        if doc_info['uploaded_by_id'] != user_id:
            cursor.execute('''
                SELECT 1 FROM project_assignments WHERE user_id = ? AND project_id = ?
            ''', (user_id, doc_info['project_id']))
            if not cursor.fetchone():
                conn.close()
                return jsonify({"error": "Permission denied"}), 403
        
        # Delete file from storage
        file_path = os.path.join('uploads', 'documents', doc_info['filename'])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError as e:
            print(f"[WARNING] Could not delete file {file_path}: {e}")
            # Continue with deletion from DB even if file deletion fails

        cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id, ))
        conn.commit()
        conn.close()

        log_activity(user_id,
                     'document_deleted',
                     f'Deleted document ID: {doc_id}',
                     project_id=doc_info['project_id'])

        return jsonify({"message": "Document deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/dashboard/stats", methods=["GET"])
@login_required
def get_employee_dashboard_stats():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT COUNT(DISTINCT id) as count FROM projects 
            WHERE created_by_id = ? OR id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
        ''', (user_id, user_id))
        total_projects = cursor.fetchone()['count']

        cursor.execute(
            'SELECT COUNT(*) as count FROM tasks WHERE assigned_to_id = ? OR created_by_id = ?',
            (user_id, user_id))
        total_tasks = cursor.fetchone()['count']

        cursor.execute(
            'SELECT COUNT(*) as count FROM tasks WHERE (assigned_to_id = ? OR created_by_id = ?) AND status = ?',
            (user_id, user_id, 'Completed'))
        completed_tasks = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM milestones m 
            WHERE m.project_id IN (
                SELECT id FROM projects WHERE created_by_id = ? OR id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                )
            )
        ''', (user_id, user_id))
        total_milestones = cursor.fetchone()['count']

        conn.close()

        return jsonify({
            "total_projects": total_projects,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "total_milestones": total_milestones,
            "pending_tasks": total_tasks - completed_tasks
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/activities", methods=["GET"])
@login_required
def get_employee_activities():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT a.id, a.activity_type, a.description, a.created_at,
                   u.username, p.title as project_title, p.description as project_description, p.deadline as project_deadline,
                   t.title as task_title, m.title as milestone_title
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN projects p ON a.project_id = p.id
            LEFT JOIN tasks t ON a.task_id = t.id
            LEFT JOIN milestones m ON a.milestone_id = m.id
            WHERE a.user_id = ? OR a.project_id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            ) OR a.task_id IN (
                SELECT id FROM tasks WHERE assigned_to_id = ? OR created_by_id = ?
            ) OR a.milestone_id IN (
                SELECT id FROM milestones WHERE project_id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                )
            )
            ORDER BY a.created_at DESC
            LIMIT 50
        ''', (user_id, user_id, user_id, user_id, user_id))

        activities = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in activities]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/search", methods=["GET"])
@login_required
def search():
    try:
        query = request.args.get('q', '').strip()
        if not query or len(query) < 2:
            return jsonify({"results": []}), 200

        # Check if admin or employee
        is_admin = session.get('admin') or session.get('user_type') == 'admin'
        user_id = get_current_user_id()

        conn = get_db_connection()
        cursor = conn.cursor()

        results = []

        # Search projects
        if is_admin:
            cursor.execute(
                '''
                SELECT 'project' as type, id, title as name, description,
                       created_at, NULL as project_name, NULL as status
                FROM projects
                WHERE title LIKE ? OR description LIKE ?
                ORDER BY created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))
        else:
            cursor.execute(
                '''
                SELECT 'project' as type, p.id, p.title as name, p.description,
                       p.created_at, NULL as project_name, NULL as status
                FROM projects p
                WHERE (p.title LIKE ? OR p.description LIKE ?) AND
                      (p.created_by_id = ? OR p.id IN (
                          SELECT project_id FROM project_assignments WHERE user_id = ?
                      ))
                ORDER BY p.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%', user_id, user_id))

        projects = cursor.fetchall()
        for project in projects:
            results.append({
                "type":
                "project",
                "id":
                project['id'],
                "name":
                project['name'],
                "description":
                project['description'][:100] + "..."
                if project['description'] and len(project['description']) > 100
                else project['description'],
                "url":
                "/admin-dashboard" if is_admin else "/employee-dashboard",
                "tab":
                "projects-tab" if not is_admin else None
            })

        # Search tasks
        if is_admin:
            cursor.execute(
                '''
                SELECT 'task' as type, t.id, t.title as name, t.description,
                       t.created_at, p.title as project_name, t.status
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                WHERE t.title LIKE ? OR t.description LIKE ?
                ORDER BY t.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))
        else:
            cursor.execute(
                '''
                SELECT 'task' as type, t.id, t.title as name, t.description,
                       t.created_at, p.title as project_name, t.status
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                WHERE (t.title LIKE ? OR t.description LIKE ?) AND
                      (t.assigned_to_id = ? OR t.created_by_id = ?)
                ORDER BY t.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%', user_id, user_id))

        tasks = cursor.fetchall()
        for task in tasks:
            results.append({
                "type":
                "task",
                "id":
                task['id'],
                "name":
                task['name'],
                "description":
                task['description'][:100] if task['description']
                and len(task['description']) > 100 else task['description'],
                "project_name":
                task['project_name'],
                "status":
                task['status'],
                "url":
                "/admin-dashboard" if is_admin else "/employee-dashboard",
                "tab":
                "tasks-tab" if not is_admin else None
            })

        # Search users (admin only)
        if is_admin:
            cursor.execute(
                '''
                SELECT 'user' as type, id, username as name, email as description,
                       created_at, NULL as project_name, NULL as status
                FROM users
                WHERE username LIKE ? OR email LIKE ?
                ORDER BY created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))

            users = cursor.fetchall()
            for user in users:
                results.append({
                    "type": "user",
                    "id": user['id'],
                    "name": user['name'],
                    "description": user['description'],
                    "url": "/admin-dashboard",
                    "tab": "users-tab"
                })

        # Search milestones
        if is_admin:
            cursor.execute(
                '''
                SELECT 'milestone' as type, m.id, m.title as name, m.description,
                       m.created_at, p.title as project_name, m.status
                FROM milestones m
                LEFT JOIN projects p ON m.project_id = p.id
                WHERE m.title LIKE ? OR m.description LIKE ?
                ORDER BY m.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))
        else:
            cursor.execute(
                '''
                SELECT 'milestone' as type, m.id, m.title as name, m.description,
                       m.created_at, p.title as project_name, m.status
                FROM milestones m
                LEFT JOIN projects p ON m.project_id = p.id
                WHERE (m.title LIKE ? OR m.description LIKE ?) AND
                      (p.created_by_id = ? OR m.project_id IN (
                          SELECT project_id FROM project_assignments WHERE user_id = ?
                      ))
                ORDER BY m.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%', user_id, user_id))

        milestones = cursor.fetchall()
        for milestone in milestones:
            results.append({
                "type":
                "milestone",
                "id":
                milestone['id'],
                "name":
                milestone['name'],
                "description":
                milestone['description'][:100]
                if milestone['description']
                and len(milestone['description']) > 100 else
                milestone['description'],
                "project_name":
                milestone['project_name'],
                "status":
                milestone['status'],
                "url":
                "/admin-dashboard" if is_admin else "/employee-dashboard",
                "tab":
                "milestones-tab" if not is_admin else None
            })

        # Search documents
        if is_admin:
            cursor.execute(
                '''
                SELECT 'document' as type, d.id, d.original_filename as name,
                       d.file_size, d.uploaded_at, p.title as project_name, NULL as status
                FROM documents d
                LEFT JOIN projects p ON d.project_id = p.id
                WHERE d.original_filename LIKE ?
                ORDER BY d.uploaded_at DESC
                LIMIT 10
            ''', (f'%{query}%', ))
        else:
            cursor.execute(
                '''
                SELECT 'document' as type, d.id, d.original_filename as name,
                       d.file_size, d.uploaded_at, p.title as project_name, NULL as status
                FROM documents d
                LEFT JOIN projects p ON d.project_id = p.id
                WHERE d.original_filename LIKE ? AND
                      (d.uploaded_by_id = ? OR d.project_id IN (
                          SELECT project_id FROM project_assignments WHERE user_id = ?
                      ))
                ORDER BY d.uploaded_at DESC
                LIMIT 10
            ''', (f'%{query}%', user_id, user_id))

        documents = cursor.fetchall()
        for doc in documents:
            results.append({
                "type": "document",
                "id": doc['id'],
                "name": doc['name'],
                "description": f"Size: {doc['file_size']} bytes",
                "project_name": doc['project_name'],
                "url":
                f"/admin-dashboard" if is_admin else f"/employee-dashboard",
                "tab": "documents-tab" if not is_admin else None
            })

        conn.close()

        return jsonify({"results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/projects", methods=["GET"])
@admin_required
def get_admin_projects():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name, 
                   p.created_at, COUNT(DISTINCT pa.user_id) as team_count,
                   COUNT(DISTINCT t.id) as task_count
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN project_assignments pa ON p.id = pa.project_id
            LEFT JOIN tasks t ON p.id = t.project_id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        ''')

        projects = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in projects]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/tasks", methods=["GET"])
@admin_required
def get_admin_tasks():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT t.id, t.title, t.description, t.status, t.priority, 
                   t.deadline, t.project_id, p.title as project_name,
                   t.assigned_to_id, u.username as assigned_to_name,
                   t.created_by_id, uc.username as created_by_name,
                   t.created_at, t.approval_status
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            ORDER BY t.created_at DESC
        ''')

        tasks = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in tasks]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


def log_activity(user_id,
                 activity_type,
                 description,
                 project_id=None,
                 task_id=None,
                 milestone_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO activities (user_id, activity_type, description, project_id, task_id, milestone_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, activity_type, description, project_id, task_id,
              milestone_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to log activity: {str(e)}")


@app.route("/api/employee/skills", methods=["GET"])
@login_required
def get_employee_skills():
    """Get all skills for the logged-in employee"""
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT id, skill_name, created_at 
            FROM user_skills 
            WHERE user_id = ?
            ORDER BY skill_name
        ''', (user_id, ))

        skills = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in skills]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/skills", methods=["POST"])
@login_required
def add_employee_skill():
    """Add a new skill for the logged-in employee"""
    try:
        data = request.get_json() or {}
        skill_name = (data.get("skill_name") or "").strip()

        if not skill_name:
            return jsonify({"error": "Skill name is required"}), 400

        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                '''
                INSERT INTO user_skills (user_id, skill_name)
                VALUES (?, ?)
            ''', (user_id, skill_name))
            conn.commit()
            skill_id = cursor.lastrowid
            conn.close()

            return jsonify({
                "id": skill_id,
                "skill_name": skill_name,
                "message": "Skill added successfully!"
            }), 201
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "Skill already exists"}), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/skills/<int:skill_id>", methods=["DELETE"])
@login_required
def delete_employee_skill(skill_id):
    """Delete a skill for the logged-in employee"""
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT id FROM user_skills WHERE id = ? AND user_id = ?',
            (skill_id, user_id))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Skill not found"}), 404

        cursor.execute('DELETE FROM user_skills WHERE id = ? AND user_id = ?',
                       (skill_id, user_id))
        conn.commit()
        conn.close()

        return jsonify({"message": "Skill deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/profile", methods=["GET"])
@login_required
def get_employee_profile():
    """Get profile for the logged-in employee"""
    try:
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role,
                   u.phone, u.department, u.bio, u.avatar_url, u.created_at
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.id = ?
        ''', (user_id, ))

        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "User not found"}), 404

        cursor.execute(
            '''
            SELECT skill_name FROM user_skills WHERE user_id = ? ORDER BY skill_name
        ''', (user_id, ))
        skills = [row['skill_name'] for row in cursor.fetchall()]

        conn.close()

        profile = dict(user)
        profile['skills'] = skills

        return jsonify(profile), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/profile", methods=["PUT"])
@login_required
def update_employee_profile():
    """Update profile for the logged-in employee with validation"""
    try:
        data = request.get_json() or {}
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401

        phone = data.get("phone", "").strip() if data.get("phone") else None
        department = data.get("department", "").strip() if data.get("department") else None
        bio = data.get("bio", "").strip() if data.get("bio") else None

        if phone and len(phone) > 20:
            return jsonify({"error": "Phone number too long"}), 400
        if department and len(department) > 100:
            return jsonify({"error": "Department name too long"}), 400
        if bio and len(bio) > 500:
            return jsonify({"error": "Bio too long"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            UPDATE users 
            SET phone = ?, department = ?, bio = ?
            WHERE id = ?
        ''', (phone, department, bio, user_id))

        conn.commit()
        conn.close()

        return jsonify({"message": "Profile updated successfully!"}), 200
    except Exception as e:
        print(f"[ERROR] Profile update failed: {str(e)}")
        return jsonify({"error": f"Update failed: {str(e)}"}), 500


@app.route("/api/admin/profile", methods=["GET"])
@admin_required
def get_admin_profile():
    """Get admin profile"""
    return jsonify({
        "name": "Super Admin",
        "email": ADMIN_EMAIL,
        "role": "Administrator",
        "department": "Administration",
        "created_at": datetime.now().isoformat()
    }), 200


def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def optimize_image(image_file, max_width=500, max_height=500):
    """
    Optimize and validate uploaded image
    Resize to reasonable dimensions and compress for efficient storage
    Returns: BytesIO object with optimized image bytes
    """
    try:
        img = Image.open(image_file)
        
        # Convert RGBA to RGB if necessary
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
            img = background
        
        # Resize image maintaining aspect ratio
        img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
        
        # Save optimized image to BytesIO
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=85, optimize=True)
        output.seek(0)
        
        return output
    except Exception as e:
        print(f"Error optimizing image: {str(e)}")
        raise

@app.route("/api/employee/profile/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    """Upload and optimize profile avatar"""
    try:
        if 'avatar' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['avatar']
        if not file.filename:
            return jsonify({"error": "No file selected"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type. Only PNG, JPG, JPEG, GIF, and WebP are allowed"}), 400

        user_id = get_current_user_id()

        # Ensure upload folder exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        # Optimize image
        try:
            optimized_image_bytes = optimize_image(file)
        except Exception as e:
            print(f"[ERROR] Failed to optimize image: {str(e)}")
            return jsonify({"error": "Failed to process image. Please try another file."}), 400

        # Generate secure filename
        filename = f"{user_id}_{secrets.token_hex(8)}.jpg"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        try:
            # Save optimized image bytes to file
            with open(file_path, 'wb') as f:
                f.write(optimized_image_bytes.getvalue())
        except Exception as save_error:
            print(f"[ERROR] Error saving avatar: {str(save_error)}")
            return jsonify({"error": "Failed to save file to server. Check folder permissions."}), 500

        # Update database with new avatar URL
        conn = get_db_connection()
        cursor = conn.cursor()
        
        avatar_url = f"/uploads/profiles/{filename}"
        
        try:
            cursor.execute('UPDATE users SET avatar_url = ? WHERE id = ?', (avatar_url, user_id))
            conn.commit()
        except sqlite3.OperationalError as db_error:
            # If column doesn't exist, add it
            if "no such column: avatar_url" in str(db_error):
                try:
                    cursor.execute('ALTER TABLE users ADD COLUMN avatar_url TEXT')
                    conn.commit()
                    cursor.execute('UPDATE users SET avatar_url = ? WHERE id = ?', (avatar_url, user_id))
                    conn.commit()
                    print(f"[INFO] Added avatar_url column for user {user_id}")
                except Exception as alter_error:
                    conn.close()
                    print(f"[ERROR] Failed to add avatar_url column: {str(alter_error)}")
                    return jsonify({"error": "Database configuration issue. Please contact administrator."}), 500
        
        conn.close()

        return jsonify({
            "message": "Profile picture uploaded successfully!",
            "avatar_url": avatar_url
        }), 200

    except Exception as e:
        print(f"[ERROR] Error uploading avatar: {str(e)}")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500


@app.route("/api/employee/profile/avatar", methods=["DELETE"])
@login_required
def delete_avatar():
    """
    Enhanced avatar deletion with proper file cleanup
    """
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT avatar_url FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

        if not user or not user['avatar_url']:
            conn.close()
            return jsonify({"error": "No profile picture found"}), 404

        # Delete file from storage
        filename = user['avatar_url'].split('/')[-1]
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError:
            pass

        # Update database
        cursor.execute('UPDATE users SET avatar_url = NULL WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()

        return jsonify({"message": "Profile picture deleted successfully!"}), 200

    except Exception as e:
        print(f"[v0] Error deleting avatar: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/uploads/profiles/<path:filename>")
def serve_profile_picture(filename):
    """
    Serve profile pictures with proper security
    Validates filename before serving
    """
    try:
        # Security check: only allow alphanumeric and underscores
        if not re.match(r'^[\w\-]+\.jpg$', filename):
            return jsonify({"error": "Invalid file"}), 400
        
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


@app.route("/api/projects/<int:project_id>/progress", methods=["GET"])
@login_required
def get_project_progress(project_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Count total tasks
        cursor.execute("SELECT COUNT(*) as total FROM tasks WHERE project_id = ?", (project_id,))
        total = cursor.fetchone()["total"]

        # Count completed tasks
        cursor.execute("SELECT COUNT(*) as completed FROM tasks WHERE project_id = ? AND status = 'Completed'", (project_id,))
        completed = cursor.fetchone()["completed"]

        # Avoid division by zero
        progress = 0
        if total > 0:
            progress = int((completed / total) * 100)

        # Save progress in DB
        cursor.execute("UPDATE projects SET progress = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (progress, project_id))
        conn.commit()
        conn.close()

        return jsonify({"project_id": project_id, "progress": progress}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents/<int:doc_id>/download", methods=["GET"])
@login_required
def download_document(doc_id):
    """Download a document file with proper error handling"""
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user has access to this document
        cursor.execute('''
            SELECT d.filename, d.original_filename, d.project_id
            FROM documents d
            WHERE d.id = ? AND (
                d.uploaded_by_id = ? OR 
                d.project_id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                ) OR
                d.project_id IN (
                    SELECT id FROM projects WHERE created_by_id = ?
                )
            )
        ''', (doc_id, user_id, user_id, user_id))
        
        doc = cursor.fetchone()
        conn.close()
        
        if not doc:
            return jsonify({"error": "Document not found or access denied"}), 404
        
        file_path = os.path.join('uploads', 'documents', doc['filename'])
        
        if not os.path.exists(file_path):
            print(f"[ERROR] File not found at path: {file_path}")
            return jsonify({"error": "File not found on server"}), 404
        
        # Log download activity
        log_activity(user_id, 'document_downloaded', 
                    f'Downloaded document: {doc["original_filename"]}',
                    project_id=doc['project_id'])
        
        return send_from_directory('uploads/documents', doc['filename'], 
                                  as_attachment=True,
                                  download_name=doc['original_filename'])
    
    except Exception as e:
        print(f"[ERROR] Document download failed: {str(e)}")
        return jsonify({"error": f"Download failed: {str(e)}"}), 500


@app.route("/api/admin/documents/<int:doc_id>/download", methods=["GET"])
@admin_required
def admin_download_document(doc_id):
    """Admin download a document file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT filename, original_filename, project_id
            FROM documents
            WHERE id = ?
        ''', (doc_id,))
        
        doc = cursor.fetchone()
        conn.close()
        
        if not doc:
            return jsonify({"error": "Document not found"}), 404
        
        file_path = os.path.join('uploads', 'documents', doc['filename'])
        
        if not os.path.exists(file_path):
            print(f"[ERROR] Admin document file not found at path: {file_path}")
            return jsonify({"error": "File not found on server"}), 404
        
        return send_from_directory('uploads/documents', doc['filename'], 
                                  as_attachment=True,
                                  download_name=doc['original_filename'])
    
    except Exception as e:
        print(f"[ERROR] Admin document download failed: {str(e)}")
        return jsonify({"error": f"Download failed: {str(e)}"}), 500


# Enhanced profile stats endpoint
@app.route("/api/employee/profile/stats", methods=["GET"])
@login_required
def get_employee_profile_stats():
    """Get detailed profile statistics for employee"""
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total projects
        cursor.execute('''
            SELECT COUNT(DISTINCT id) as count FROM projects 
            WHERE created_by_id = ? OR id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
        ''', (user_id, user_id))
        total_projects = cursor.fetchone()['count']
        
        # Completed tasks
        cursor.execute('''
            SELECT COUNT(*) as count FROM tasks 
            WHERE (assigned_to_id = ? OR created_by_id = ?) AND status = 'Completed'
        ''', (user_id, user_id))
        completed_tasks = cursor.fetchone()['count']
        
        # Pending tasks
        cursor.execute('''
            SELECT COUNT(*) as count FROM tasks 
            WHERE (assigned_to_id = ? OR created_by_id = ?) 
            AND status != 'Completed'
        ''', (user_id, user_id))
        pending_tasks = cursor.fetchone()['count']
        
        # Total milestones
        cursor.execute('''
            SELECT COUNT(*) as count FROM milestones m
            WHERE m.project_id IN (
                SELECT id FROM projects WHERE created_by_id = ? 
                OR id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
            )
        ''', (user_id, user_id))
        total_milestones = cursor.fetchone()['count']
        
        # Completed milestones
        cursor.execute('''
            SELECT COUNT(*) as count FROM milestones m
            WHERE m.status = 'Completed' AND m.project_id IN (
                SELECT id FROM projects WHERE created_by_id = ? 
                OR id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
            )
        ''', (user_id, user_id))
        completed_milestones = cursor.fetchone()['count']
        
        # Documents uploaded
        cursor.execute('''
            SELECT COUNT(*) as count FROM documents WHERE uploaded_by_id = ?
        ''', (user_id,))
        documents_uploaded = cursor.fetchone()['count']
        
        conn.close()
        
        return jsonify({
            "total_projects": total_projects,
            "completed_tasks": completed_tasks,
            "pending_tasks": pending_tasks,
            "total_milestones": total_milestones,
            "completed_milestones": completed_milestones,
            "documents_uploaded": documents_uploaded,
            "completion_rate": round((completed_tasks / (completed_tasks + pending_tasks) * 100), 2) if (completed_tasks + pending_tasks) > 0 else 0
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/admin/projects/realtime", methods=["GET"])
@admin_required
def get_admin_realtime_projects():
    """Get real-time project updates for admin dashboard"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress,
                   p.deadline, p.reporting_time, p.created_at, p.updated_at,
                   u.username as creator_name,
                   COUNT(DISTINCT t.id) as total_tasks,
                   SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                   COUNT(DISTINCT m.id) as total_milestones,
                   SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                   COUNT(DISTINCT pa.user_id) as team_size
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            LEFT JOIN project_assignments pa ON p.id = pa.project_id
            WHERE p.status != 'Completed'
            GROUP BY p.id
            ORDER BY p.updated_at DESC
        ''')
        
        projects = cursor.fetchall()
        conn.close()
        
        result = []
        for row in projects:
            project_dict = dict(row)
            project_dict['completed_tasks'] = project_dict.get('completed_tasks') or 0
            project_dict['total_tasks'] = project_dict.get('total_tasks') or 0
            project_dict['completed_milestones'] = project_dict.get('completed_milestones') or 0
            project_dict['total_milestones'] = project_dict.get('total_milestones') or 0
            project_dict['progress'] = project_dict.get('progress') or 0
            result.append(project_dict)
        
        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] Admin realtime projects error: {str(e)}")
        return jsonify({"error": str(e)}), 500


# Get specific project details for admin
@app.route("/api/admin/projects/<int:project_id>", methods=["GET"])
@admin_required
def get_admin_project_detail(project_id):
    """Get detailed project information"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.username as creator_name,
                   COUNT(DISTINCT t.id) as total_tasks,
                   COUNT(DISTINCT m.id) as total_milestones
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            WHERE p.id = ?
            GROUP BY p.id
        ''', (project_id,))
        
        project = cursor.fetchone()
        conn.close()
        
        if not project:
            return jsonify({"error": "Project not found"}), 404
        
        return jsonify(dict(project)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Get specific task details for admin
@app.route("/api/admin/tasks/<int:task_id>", methods=["GET"])
@admin_required
def get_admin_task_detail(task_id):
    """Get detailed task information"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.*, p.title as project_name,
                   u.username as assigned_to_name,
                   uc.username as created_by_name
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            WHERE t.id = ?
        ''', (task_id,))
        
        task = cursor.fetchone()
        conn.close()
        
        if not task:
            return jsonify({"error": "Task not found"}), 404
        
        return jsonify(dict(task)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Employee real-time projects endpoint with live progress calculation
@app.route("/api/employee/projects/realtime", methods=["GET"])
@login_required
def get_employee_realtime_projects():
    """Get real-time project updates with calculated progress percentage"""
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT p.id, p.title, p.description, p.status,
                   p.deadline, p.reporting_time, p.created_at, p.updated_at,
                   u.username as creator_name,
                   COUNT(DISTINCT t.id) as total_tasks,
                   SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                   COUNT(DISTINCT m.id) as total_milestones,
                   SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                   COUNT(DISTINCT pa.user_id) as team_size
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            LEFT JOIN project_assignments pa ON p.id = pa.project_id
            WHERE (p.created_by_id = ? OR p.id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )) AND p.status != 'Completed'
            GROUP BY p.id
            ORDER BY p.updated_at DESC
        ''', (user_id, user_id))
        
        projects = cursor.fetchall()
        
        # Calculate live progress percentage for each project
        result = []
        for row in projects:
            project_dict = dict(row)
            total_tasks = project_dict.get('total_tasks') or 0
            completed_tasks = project_dict.get('completed_tasks') or 0
            total_milestones = project_dict.get('total_milestones') or 0
            completed_milestones = project_dict.get('completed_milestones') or 0
            
            # Calculate progress: if no tasks, progress is 0
            if total_tasks > 0:
                progress = int((completed_tasks / total_tasks) * 100)
            elif total_milestones > 0:
                progress = int((completed_milestones / total_milestones) * 100)
            else:
                progress = 0
            
            project_dict['progress'] = progress
            project_dict['completed_tasks'] = completed_tasks
            project_dict['total_tasks'] = total_tasks
            project_dict['completed_milestones'] = completed_milestones
            project_dict['total_milestones'] = total_milestones
            result.append(project_dict)
        
        conn.close()
        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] Realtime projects error: {str(e)}")
        conn.close()
        return jsonify({"error": str(e)}), 500




def check_db_initialized():
    """Check if database has required tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'")
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except:
        return False

if not os.path.exists(DATABASE) or not check_db_initialized():
    init_db()

migrate_db()


def update_project_status(project_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get total + completed tasks
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) as completed
        FROM tasks 
        WHERE project_id = ?
    """, (project_id,))
    row = cursor.fetchone()

    total = row['total']
    completed = row['completed']

    # Decide project status
    new_status = None
    if total == 0:
        new_status = 'Pending'
    elif completed == total:
        new_status = 'Completed'
    else:
        new_status = 'In Progress'

    cursor.execute(
        "UPDATE projects SET status = ? WHERE id = ?",
        (new_status, project_id)
    )

    conn.commit()
    conn.close()

@app.route("/api/admin/employees/<int:employee_id>/profile", methods=["GET"])
@admin_required
def get_employee_profile_admin(employee_id):
    """Admin endpoint to get an employee's profile details"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role,
                   u.phone, u.department, u.bio, u.avatar_url, u.created_at
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.id = ?
        ''', (employee_id,))

        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "Employee not found"}), 404

        # Get skills
        cursor.execute('''
            SELECT skill_name FROM user_skills WHERE user_id = ? ORDER BY skill_name
        ''', (employee_id,))
        skills = [row['skill_name'] for row in cursor.fetchall()]

        # Get stats
        cursor.execute('''
            SELECT COUNT(DISTINCT id) as count FROM projects 
            WHERE created_by_id = ? OR id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
        ''', (employee_id, employee_id))
        projects_count = cursor.fetchone()['count']

        cursor.execute('''
            SELECT COUNT(*) as count FROM tasks 
            WHERE assigned_to_id = ? AND status = 'Completed'
        ''', (employee_id,))
        tasks_completed = cursor.fetchone()['count']

        cursor.execute('''
            SELECT COUNT(*) as count FROM documents WHERE uploaded_by_id = ?
        ''', (employee_id,))
        documents_count = cursor.fetchone()['count']

        conn.close()

        profile = dict(user)
        profile['skills'] = skills
        profile['stats'] = {
            'projects': projects_count,
            'tasks_completed': tasks_completed,
            'documents': documents_count
        }

        return jsonify(profile), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
