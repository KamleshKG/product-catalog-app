from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import json
import os
from functools import wraps
import time
import logging
from flask_session import Session
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import redis

app = Flask(__name__)

# --- Configure Session using Redis ---
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0)
app.config["SESSION_REDIS_URL"] = 'redis://localhost:6379/0'
REDIS_URL = 'redis://localhost:6379/0'

Session(app)

# --- Prometheus Metrics ---
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP Requests')
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP Request Latency (seconds)')
LOGIN_SUCCESS_COUNT = Counter('login_success_total', 'Total Successful Logins')
LOGIN_FAILURE_COUNT = Counter('login_failure_total', 'Total Failed Logins')
PRODUCT_ADD_COUNT = Counter('product_add_total', 'Total Products Added')
PRODUCT_EDIT_COUNT = Counter('product_edit_total', 'Total Products Edited')
PRODUCT_DELETE_COUNT = Counter('product_delete_total', 'Total Products Deleted')

# --- Logging Configuration ---
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(filename=os.path.join(log_dir, 'app.log'), level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s')

# --- RBAC Configuration ---
ROLES = {
    "guest": {"permissions": ["view_products"]},
    "customer": {"permissions": ["view_products", "add_to_cart"]},
    "admin": {"permissions": ["view_products", "add_to_cart", "manage_products", "view_dashboard"]},
}

# --- User Configuration ---
USERS_FILE = os.environ.get('USERS_FILE', 'data/users.json')
try:
    with open(USERS_FILE, 'r') as f:
        USERS = json.load(f)
except FileNotFoundError:
    USERS = {
        "guest_user": {"password": "guest_password", "role": "guest"},
        "customer1": {"password": "customer_password", "role": "customer"},
        "admin1": {"password": "admin_password", "role": "admin"},
    }
    with open(USERS_FILE, 'w') as f:
        json.dump(USERS, f, indent=2)
    logging.warning(f"USERS_FILE not found, created default at {USERS_FILE}")

# --- Deployment History File ---
DEPLOYMENT_HISTORY_FILE = 'deployment_history.json'

def get_deployment_history():
    try:
        with open(DEPLOYMENT_HISTORY_FILE, 'r') as f:
            history = json.load(f)
            history.sort(key=lambda x: x.get('timestamp', '0'), reverse=True)
            return history
    except FileNotFoundError:
        return []

def get_current_environment():
    try:
        with open('kubernetes/service.yaml', 'r') as f:
            service_yaml = f.read()
            if 'environment: green' in service_yaml:
                return "Green"
            elif 'environment: blue' in service_yaml:
                return "Blue"
            else:
                return "Unknown"
    except FileNotFoundError:
        return "Unknown"

def check_permission(permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            REQUEST_COUNT.inc()
            start_time = time.time()
            try:
                if 'user_role' not in session:
                    flash("You need to log in to access this page.", 'warning')
                    return redirect(url_for('login'))
                user_role = session['user_role']
                if user_role not in ROLES or permission not in ROLES[user_role]['permissions']:
                    flash("You do not have permission to access this page.", 'danger')
                    return redirect(url_for('index'))
                return func(*args, **kwargs)
            finally:
                REQUEST_LATENCY.observe(time.time() - start_time)
        return wrapper
    return decorator

# --- Data Handling ---
PRODUCTS_FILE = os.environ.get('PRODUCTS_FILE', 'data/products.json')

def load_products():
    try:
        with open(PRODUCTS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_products(products):
    with open(PRODUCTS_FILE, 'w') as f:
        json.dump(products, f, indent=2)

# --- Audit Logging ---
AUDIT_LOG_FILE = os.environ.get('AUDIT_LOG_FILE', 'data/audit.log')

def log_audit(action, user=None, details=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_entry = f"{timestamp} - {action}"
    if user:
        log_entry += f" - User: {user}"
    if details:
        log_entry += f" - Details: {json.dumps(details)}"
    with open(AUDIT_LOG_FILE, 'a') as f:
        f.write(log_entry + '\n')
    logging.info(f"Audit: {log_entry}")

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('product_list'))

@app.route('/products')
@check_permission('view_products')
def product_list():
    products = load_products()
    return render_template('product_list.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in USERS and USERS[username]['password'] == password:
            session['user'] = username
            session['user_role'] = USERS[username]['role']
            LOGIN_SUCCESS_COUNT.inc()
            flash(f"Logged in as {username}", 'success')
            log_audit("User logged in", user=username)
            return redirect(url_for('product_list'))
        else:
            LOGIN_FAILURE_COUNT.inc()
            flash("Invalid username or password", 'danger')
            log_audit("Login failed", user=username)
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = session.get('user')
    session.pop('user', None)
    session.pop('user_role', None)
    flash("Logged out successfully", 'info')
    log_audit("User logged out", user=user)
    return redirect(url_for('index'))

@app.route('/products/add', methods=['GET', 'POST'])
@check_permission('manage_products')
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        new_product = {
            "id": len(load_products()) + 1,
            "name": name,
            "description": description,
            "price": price,
            "category": category
        }
        products = load_products()
        products.append(new_product)
        save_products(products)
        PRODUCT_ADD_COUNT.inc()
        flash("Product added successfully!", 'success')
        log_audit("Product added", user=session.get('user'), details=new_product)
        return redirect(url_for('product_list'))
    return render_template('add_product.html')

@app.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@check_permission('manage_products')
def edit_product(product_id):
    products = load_products()
    product = next((p for p in products if p['id'] == product_id), None)
    if not product:
        flash("Product not found.", 'warning')
        return redirect(url_for('product_list'))

    if request.method == 'POST':
        old_product = product.copy()
        product['name'] = request.form['name']
        product['description'] = request.form['description']
        product['price'] = float(request.form['price'])
        product['category'] = request.form['category']
        save_products(products)
        PRODUCT_EDIT_COUNT.inc()
        flash("Product updated successfully!", 'success')
        log_audit("Product updated", user=session.get('user'), details={"old": old_product, "new": product})
        return redirect(url_for('product_list'))

    return render_template('edit_product.html', product=product)

@app.route('/products/delete/<int:product_id>')
@check_permission('manage_products')
def delete_product(product_id):
    products = load_products()
    product_to_delete = next((p for p in products if p['id'] == product_id), None)
    initial_length = len(products)
    products = [p for p in products if p['id'] != product_id]
    if len(products) < initial_length:
        save_products(products)
        PRODUCT_DELETE_COUNT.inc()
        flash("Product deleted successfully!", 'success')
        log_audit("Product deleted", user=session.get('user'), details={"id": product_id, "name": product_to_delete.get('name') if product_to_delete else 'Unknown'})
    else:
        flash("Product not found.", 'warning')
    return redirect(url_for('product_list'))

@app.route('/dashboard')
@check_permission('view_dashboard')
def dashboard():
    deployment_history = get_deployment_history()
    current_env = get_current_environment()
    return render_template('dashboard.html',
                           product_add_count=PRODUCT_ADD_COUNT._value,
                           product_edit_count=PRODUCT_EDIT_COUNT._value,
                           product_delete_count=PRODUCT_DELETE_COUNT._value,
                           login_attempt_count=LOGIN_FAILURE_COUNT._value + LOGIN_SUCCESS_COUNT._value,
                           login_success_count=LOGIN_SUCCESS_COUNT._value,
                           deployment_history=deployment_history,
                           current_environment=current_env)

@app.route('/metrics')
def metrics():
    return generate_latest()

@app.route('/rectify/<commit_hash>')
@check_permission('manage_products')
def rectify(commit_hash):
    flash(f"Initiating 'rectify' for commit: {commit_hash}. In a real system, this would trigger a process.", 'info')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Service running on port {port}")
    app.run(port=port)