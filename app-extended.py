from flask import Flask, jsonify, request, render_template, redirect, session
from flask_cors import CORS
import sqlite3
import secrets
import json
import re
from datetime import datetime, timezone
from functools import wraps
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)
app.secret_key = secrets.token_hex(32)

DATABASE = 'admin_system.db'

def get_db_connection():
    """Get a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not session_token:
            return jsonify({"error": "Unauthorized"}), 401
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"error": "Invalid session"}), 401
        
        return f(*args, **kwargs)
    return decorated_function


# Projects APIs
@app.route("/api/employee/projects", methods=["GET"])
@login_required
def get_employee_projects():
    """Get all projects for the logged-in employee"""
    try:
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress, p.deadline, 
                   p.created_by_id, p.created_at, u.username as creator_name
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
    """Create a new project if permission granted"""
    try:
        data = request.get_json() or {}
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        deadline = data.get("deadline")
        
        if not title:
            return jsonify({"error": "Project title is required"}), 400
        
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        # Check permission
        cursor.execute('''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'Proj', 'Add'))
        perm = cursor.fetchone()
        
        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied: You don't have permission to create projects"}), 403
        
        cursor.execute('''
            INSERT INTO projects (title, description, deadline, created_by_id)
            VALUES (?, ?, ?, ?)
        ''', (title, description, deadline or None, user_id))
        
        conn.commit()
        project_id = cursor.lastrowid
        
        cursor.execute('''
            INSERT INTO project_assignments (user_id, project_id)
            VALUES (?, ?)
        ''', (user_id, project_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "id": project_id,
            "title": title,
            "message": "Project created successfully!"
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Tasks APIs
@app.route("/api/employee/tasks", methods=["GET"])
@login_required
def get_employee_tasks():
    """Get all tasks for the logged-in employee"""
    try:
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        cursor.execute('''
            SELECT t.id, t.title, t.description, t.status, t.priority, t.deadline,
                   t.project_id, p.title as project_name, t.assigned_to_id, t.created_by_id, t.created_at
            FROM tasks t 
            LEFT JOIN projects p ON t.project_id = p.id
            WHERE t.assigned_to_id = ? OR t.created_by_id = ?
            ORDER BY t.deadline ASC
        ''', (user_id, user_id))
        
        tasks = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in tasks]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/tasks", methods=["POST"])
@login_required
def create_employee_task():
    """Create a new task if permission granted"""
    try:
        data = request.get_json() or {}
        project_id = data.get("project_id")
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        priority = data.get("priority", "Medium")
        deadline = data.get("deadline")
        
        if not project_id or not title:
            return jsonify({"error": "Project and title are required"}), 400
        
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        # Check permission
        cursor.execute('''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'task', 'Add'))
        perm = cursor.fetchone()
        
        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied: You don't have permission to create tasks"}), 403
        
        cursor.execute('''
            INSERT INTO tasks (title, description, priority, deadline, project_id, created_by_id, assigned_to_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (title, description, priority, deadline or None, project_id, user_id, user_id))
        
        conn.commit()
        task_id = cursor.lastrowid
        conn.close()
        
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
    """Mark a task as complete"""
    try:
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        cursor.execute('''
            UPDATE tasks SET status = ?, completed_at = CURRENT_TIMESTAMP
            WHERE id = ? AND (assigned_to_id = ? OR created_by_id = ?)
        ''', ('Completed', task_id, user_id, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Task completed successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Milestones APIs
@app.route("/api/employee/milestones", methods=["GET"])
@login_required
def get_employee_milestones():
    """Get all milestones for projects accessible to employee"""
    try:
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        cursor.execute('''
            SELECT m.id, m.title, m.description, m.due_date, m.status, m.project_id, p.title as project_name
            FROM milestones m 
            LEFT JOIN projects p ON m.project_id = p.id
            WHERE p.created_by_id = ? OR p.id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
            ORDER BY m.due_date ASC
        ''', (user_id, user_id))
        
        milestones = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in milestones]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/milestones", methods=["POST"])
@login_required
def create_employee_milestone():
    """Create a new milestone if permission granted"""
    try:
        data = request.get_json() or {}
        project_id = data.get("project_id")
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        due_date = data.get("due_date")
        
        if not project_id or not title:
            return jsonify({"error": "Project and title are required"}), 400
        
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        # Check permission
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
        
        return jsonify({
            "id": milestone_id,
            "title": title,
            "message": "Milestone created successfully!"
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/milestones/<int:milestone_id>/complete", methods=["POST"])
@login_required
def complete_employee_milestone(milestone_id):
    """Mark a milestone as complete"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE milestones SET status = ?
            WHERE id = ?
        ''', ('Completed', milestone_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Milestone completed successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Documents APIs
@app.route("/api/employee/documents", methods=["GET"])
@login_required
def get_employee_documents():
    """Get all documents"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT d.id, d.filename, d.original_filename, d.file_size, d.uploaded_at,
                   d.uploaded_by_id, u.username as uploader_name, d.project_id, p.title as project_name
            FROM documents d 
            LEFT JOIN users u ON d.uploaded_by_id = u.id
            LEFT JOIN projects p ON d.project_id = p.id
            ORDER BY d.uploaded_at DESC
        ''')
        
        documents = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(row) for row in documents]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/documents/upload", methods=["POST"])
@login_required
def upload_employee_document():
    """Upload a document if permission granted"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        project_id = request.form.get('project_id')
        
        if not file.filename or not project_id:
            return jsonify({"error": "File and project ID are required"}), 400
        
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        # Check permission
        cursor.execute('''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'Proj_doc', 'Add'))
        perm = cursor.fetchone()
        
        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied"}), 403
        
        # Create uploads folder if it doesn't exist
        os.makedirs('uploads', exist_ok=True)
        
        # Save file
        filename = f"{int(datetime.now().timestamp())}_{file.filename}"
        file.save(f"uploads/{filename}")
        
        cursor.execute('''
            INSERT INTO documents (filename, original_filename, file_size, uploaded_by_id, project_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, file.filename, len(file.read()), user_id, project_id))
        
        conn.commit()
        doc_id = cursor.lastrowid
        conn.close()
        
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
    """Delete a document if permission granted"""
    try:
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        # Check permission
        cursor.execute('''
            SELECT granted FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, 'Proj_doc', 'Delete'))
        perm = cursor.fetchone()
        
        if not perm or not perm['granted']:
            conn.close()
            return jsonify({"error": "Permission denied"}), 403
        
        cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Document deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Dashboard Stats APIs
@app.route("/api/employee/dashboard/stats", methods=["GET"])
@login_required
def get_employee_dashboard_stats():
    """Get dashboard statistics for the logged-in employee"""
    try:
        session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM user_sessions WHERE session_token = ?', (session_token,))
        user_result = cursor.fetchone()
        user_id = user_result['user_id'] if user_result else None
        
        # Total projects
        cursor.execute('SELECT COUNT(*) as count FROM projects WHERE created_by_id = ?', (user_id,))
        total_projects = cursor.fetchone()['count']
        
        # Total tasks
        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE assigned_to_id = ? OR created_by_id = ?', (user_id, user_id))
        total_tasks = cursor.fetchone()['count']
        
        # Completed tasks
        cursor.execute('SELECT COUNT(*) as count FROM tasks WHERE (assigned_to_id = ? OR created_by_id = ?) AND status = ?', (user_id, user_id, 'Completed'))
        completed_tasks = cursor.fetchone()['count']
        
        # Total milestones
        cursor.execute('''
            SELECT COUNT(*) as count FROM milestones m 
            WHERE m.project_id IN (
                SELECT id FROM projects WHERE created_by_id = ? OR id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                )
            )
        ''', (user_id, user_id))
        total_milestones = cursor.fetchone()['count']
        
        # Total documents
        cursor.execute('SELECT COUNT(*) as count FROM documents')
        total_documents = cursor.fetchone()['count']
        
        conn.close()
        
        return jsonify({
            "total_projects": total_projects,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "total_milestones": total_milestones,
            "total_documents": total_documents,
            "pending_tasks": total_tasks - completed_tasks
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
