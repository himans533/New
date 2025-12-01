from flask import Flask, jsonify, request, render_template, redirect, session, url_for
from flask_cors import CORS
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import json
import re
import os
from datetime import datetime, timezone, timedelta

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)
app.secret_key = secrets.token_hex(32)

DATABASE = 'admin_system.db'

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'anubha@gmail.com').lower()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Anubha@#46')
ADMIN_PIN = os.environ.get('ADMIN_PIN', '468101')
ADMIN_OTP = os.environ.get('ADMIN_OTP', '654321')

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
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
        created_by_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id)
    )''')

    cursor.execute('''CREATE TABLE project_assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (project_id) REFERENCES projects(id),
        UNIQUE(user_id, project_id)
    )''')

    cursor.execute('''CREATE TABLE document_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER NOT NULL,
        version_number INTEGER NOT NULL,
        filename TEXT NOT NULL,
        uploaded_by_id INTEGER NOT NULL,
        file_size INTEGER,
        is_current BOOLEAN DEFAULT 0,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (document_id) REFERENCES documents(id),
        FOREIGN KEY (uploaded_by_id) REFERENCES users(id)
    )''')

    cursor.execute('''CREATE TABLE document_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        document_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (document_id) REFERENCES documents(id),
        FOREIGN KEY (author_id) REFERENCES users(id)
    )''')

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

    conn.commit()
    conn.close()
    print("[OK] Database initialized successfully!")

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def validate_password_complexity(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter."
    special_chars = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
    if special_chars < 2:
        return False, "Password must contain at least two special characters."
    return True, "Password is valid."

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'employee':
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_current_user_id():
    return session.get('user_id')

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

    return jsonify({
        "message": "OTP has been sent to your registered email (simulated)."
    }), 200

@app.route("/api/admin/login/step2", methods=["POST"])
def login_step2():
    data = request.get_json() or {}
    otp = data.get("otp") or ""

    if not otp:
        return jsonify({"error": "OTP is required."}), 400

    if otp != ADMIN_OTP:
        return jsonify({"error": "Invalid OTP provided."}), 400

    session_token = secrets.token_urlsafe(32)
    
    return jsonify({
        "session_token": session_token,
        "admin_name": "Super Admin",
        "success": True,
        "message": "Login successful"
    }), 200

@app.route("/api/admin/dashboard/stats", methods=["GET"])
def get_admin_dashboard_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as count FROM projects WHERE status = ?', ('Active',))
        active_projects = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE status = ?', ('Completed',))
        completed_tasks = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE status = ?', ('In Progress',))
        active_tasks = cursor.fetchone()['count']
        
        cursor.execute('''
            SELECT COUNT(*) as count FROM tasks 
            WHERE deadline < date('now') AND status != ? AND status != ?
        ''', ('Completed', 'Overdue'))
        overdue_tasks = cursor.fetchone()['count']
        
        cursor.execute('''
            SELECT COUNT(*) as count FROM tasks 
            WHERE approval_status = ? OR approval_status IS NULL
        ''', ('pending',))
        pending_approvals = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM users')
        total_users = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM usertypes')
        total_user_types = cursor.fetchone()['count']
        
        conn.close()
        
        return jsonify({
            "active_projects": active_projects,
            "completed_tasks": completed_tasks,
            "active_tasks": active_tasks,
            "overdue_tasks": overdue_tasks,
            "pending_approvals": pending_approvals,
            "total_users": total_users,
            "total_user_types": total_user_types
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/users/<int:user_id>/permissions", methods=["GET"])
def get_user_permissions(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (user_id,))
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

        cursor.execute('DELETE FROM user_permissions WHERE user_id = ?', (user_id,))

        for module, actions in permissions.items():
            if isinstance(actions, dict):
                for action, granted in actions.items():
                    cursor.execute('''
                        INSERT INTO user_permissions (user_id, module, action, granted)
                        VALUES (?, ?, ?, ?)
                    ''', (user_id, module, action, 1 if granted else 0))

        conn.commit()
        conn.close()

        return jsonify({"message": "Permissions updated successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/usertypes", methods=["GET"])
def get_user_types():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, user_role, created_at FROM usertypes ORDER BY user_role')
        user_types = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in user_types]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/usertypes", methods=["POST"])
def create_user_type():
    try:
        data = request.get_json() or {}
        user_role = (data.get("user_role") or "").strip()

        if not user_role:
            return jsonify({"error": "User role is required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('INSERT INTO usertypes (user_role) VALUES (?)', (user_role,))
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
def update_user_type(id):
    try:
        data = request.get_json() or {}
        user_role = (data.get("user_role") or "").strip()

        if not user_role:
            return jsonify({"error": "User role is required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?', (id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User type not found."}), 404

        try:
            cursor.execute('UPDATE usertypes SET user_role = ? WHERE id = ?', (user_role, id))
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
def delete_user_type(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?', (id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User type not found."}), 404

        cursor.execute('SELECT COUNT(*) as count FROM users WHERE user_type_id = ?', (id,))
        if cursor.fetchone()['count'] > 0:
            conn.close()
            return jsonify({"error": "Cannot delete user type that has associated users."}), 400

        cursor.execute('DELETE FROM usertypes WHERE id = ?', (id,))
        conn.commit()
        conn.close()

        return jsonify({"message": "User type deleted successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/users", methods=["GET"])
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

        if not all([username, email, password, confirm_password, user_type_id]):
            return jsonify({"error": "All mandatory fields are required."}), 400

        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters."}), 400

        if "@" not in email or "." not in email.split("@")[-1]:
            return jsonify({"error": "Invalid email format."}), 400

        is_valid, validation_message = validate_password_complexity(password)
        if not is_valid:
            return jsonify({"error": validation_message}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?', (user_type_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Invalid user type selected."}), 400

        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            cursor.execute('''
                INSERT INTO users (username, email, password, user_type_id) 
                VALUES (?, ?, ?, ?)
            ''', (username, email, hashed_password, user_type_id))
            conn.commit()

            user_id = cursor.lastrowid

            for module, actions in permissions.items():
                if isinstance(actions, dict):
                    for action, granted in actions.items():
                        try:
                            cursor.execute('''
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
def get_user(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role, u.created_at
            FROM users u 
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE u.id = ?
        ''', (id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({"error": "User not found."}), 404
        
        cursor.execute('''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (id,))
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
            return jsonify({"error": "Username, email, and user type are required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM users WHERE id = ?', (id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User not found."}), 404

        try:
            if password:
                is_valid, validation_message = validate_password_complexity(password)
                if not is_valid:
                    conn.close()
                    return jsonify({"error": validation_message}), 400
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                cursor.execute('''
                    UPDATE users SET username = ?, email = ?, password = ?, user_type_id = ?
                    WHERE id = ?
                ''', (username, email, hashed_password, user_type_id, id))
            else:
                cursor.execute('''
                    UPDATE users SET username = ?, email = ?, user_type_id = ?
                    WHERE id = ?
                ''', (username, email, user_type_id, id))

            cursor.execute('DELETE FROM user_permissions WHERE user_id = ?', (id,))
            
            for module, actions in permissions.items():
                if isinstance(actions, dict):
                    for action, granted in actions.items():
                        try:
                            cursor.execute('''
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
def delete_user(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM users WHERE id = ?', (id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User not found."}), 404

        cursor.execute('DELETE FROM user_permissions WHERE user_id = ?', (id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (id,))
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
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.password, ut.user_role
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.email = ?
        ''', (email,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({"error": "Invalid email or password."}), 401

        if not check_password_hash(user['password'], password):
            conn.close()
            return jsonify({"error": "Invalid email or password."}), 401

        cursor.execute('''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (user['id'],))
        permissions_rows = cursor.fetchall()
        conn.close()

        permissions = {}
        for perm in permissions_rows:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])

        session['user_id'] = user['id']
        session['user_type'] = 'employee'
        session['username'] = user['username']

        return jsonify({
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "user_role": user['user_role'],
            "permissions": permissions,
            "message": "Login successful!"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/user/logout", methods=["POST"])
def user_logout():
    session.clear()
    return jsonify({"message": "Logout successful!"}), 200

@app.route("/api/employee/projects", methods=["GET"])
@login_required
def get_employee_projects():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
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
        team_members = data.get("team_members") or []
        
        if not title:
            return jsonify({"error": "Project title is required"}), 400
        
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'Proj', 'Add'))
        perm = cursor.fetchone()
        
        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied"}), 403
        
        cursor.execute('''
            INSERT INTO projects (title, description, deadline, created_by_id)
            VALUES (?, ?, ?, ?)
        ''', (title, description, deadline or None, user_id))
        
        project_id = cursor.lastrowid
        
        for member_id in team_members:
            try:
                cursor.execute('''
                    INSERT INTO project_assignments (user_id, project_id)
                    VALUES (?, ?)
                ''', (member_id, project_id))
            except sqlite3.IntegrityError:
                pass
        
        conn.commit()
        conn.close()

        log_activity(user_id, 'project_created', f'Created project: {title}', project_id=project_id)
        
        return jsonify({
            "id": project_id,
            "title": title,
            "message": "Project created successfully!"
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
        
        cursor.execute('''
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
        
        cursor.execute('''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'task', 'Add'))
        perm = cursor.fetchone()
        
        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied"}), 403
        
        cursor.execute('''
            INSERT INTO tasks (title, description, project_id, created_by_id, assigned_to_id, priority, deadline)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (title, description, project_id, user_id, assigned_to_id, priority, deadline or None))
        
        conn.commit()
        task_id = cursor.lastrowid
        conn.close()

        log_activity(user_id, 'task_created', f'Created task: {title}', project_id=project_id, task_id=task_id)
        
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

        cursor.execute('''
            SELECT status FROM tasks WHERE id = ? AND (assigned_to_id = ? OR created_by_id = ?)
        ''', (task_id, user_id, user_id))
        task = cursor.fetchone()

        if not task:
            conn.close()
            return jsonify({"error": "Task not found or you don't have permission to complete it."}), 404
        
        if task['status'] == 'Completed':
            conn.close()
            return jsonify({"message": "Task is already completed."}), 200

        cursor.execute('''
            UPDATE tasks SET status = ?, completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', ('Completed', task_id))

        conn.commit()
        conn.close()

        log_activity(user_id, 'task_completed', f'Completed task ID: {task_id}', task_id=task_id)

        return jsonify({"message": "Task completed successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/milestones", methods=["POST"])
@login_required
def create_employee_milestone():
    try:
        data = request.get_json() or {}
        project_id = data.get("project_id")
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        due_date = data.get("due_date")
        
        if not project_id or not title:
            return jsonify({"error": "Project and title are required"}), 400
        
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'Proj', 'Add'))
        perm = cursor.fetchone()
        
        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied"}), 403
        
        cursor.execute('''
            INSERT INTO milestones (title, description, due_date, project_id)
            VALUES (?, ?, ?, ?)
        ''', (title, description, due_date or None, project_id))
        
        conn.commit()
        milestone_id = cursor.lastrowid
        conn.close()

        log_activity(user_id, 'milestone_created', f'Created milestone: {title}', project_id=project_id, milestone_id=milestone_id)
        
        return jsonify({
            "id": milestone_id,
            "title": title,
            "message": "Milestone created successfully!"
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/milestones", methods=["GET"])
@login_required
def get_employee_milestones():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
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

@app.route("/api/employee/milestones/<int:milestone_id>/complete", methods=["POST"])
@login_required
def complete_employee_milestone(milestone_id):
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE milestones SET status = ?
            WHERE id = ?
        ''', ('Completed', milestone_id))

        conn.commit()
        conn.close()

        log_activity(user_id, 'milestone_completed', f'Completed milestone ID: {milestone_id}', milestone_id=milestone_id)

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
        
        cursor.execute('''
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

        os.makedirs('uploads', exist_ok=True)

        filename = f"{secrets.token_hex(8)}_{file.filename}"
        file_path = os.path.join('uploads', filename)
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO documents (filename, original_filename, file_size, uploaded_by_id, project_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, file.filename, file_size, user_id, project_id))

        conn.commit()
        doc_id = cursor.lastrowid
        conn.close()

        log_activity(user_id, 'document_uploaded', f'Uploaded document: {file.filename}', project_id=project_id)

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

        cursor.execute('SELECT uploaded_by_id, project_id FROM documents WHERE id = ?', (doc_id,))
        doc_info = cursor.fetchone()

        if not doc_info:
            conn.close()
            return jsonify({"error": "Document not found."}), 404

        cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        conn.commit()
        conn.close()

        log_activity(user_id, 'document_deleted', f'Deleted document ID: {doc_id}', project_id=doc_info['project_id'])

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
        
        cursor.execute('''
            SELECT COUNT(DISTINCT id) as count FROM projects 
            WHERE created_by_id = ? OR id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
        ''', (user_id, user_id))
        total_projects = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE assigned_to_id = ? OR created_by_id = ?', (user_id, user_id))
        total_tasks = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE (assigned_to_id = ? OR created_by_id = ?) AND status = ?', (user_id, user_id, 'Completed'))
        completed_tasks = cursor.fetchone()['count']
        
        cursor.execute('''
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

        cursor.execute('''
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

@app.route("/api/admin/projects", methods=["GET"])
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

def log_activity(user_id, activity_type, description, project_id=None, task_id=None, milestone_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO activities (user_id, activity_type, description, project_id, task_id, milestone_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, activity_type, description, project_id, task_id, milestone_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to log activity: {str(e)}")

if not os.path.exists(DATABASE):
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
