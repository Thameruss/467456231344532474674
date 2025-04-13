from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import os
import time
import uuid
import json
import base64
from functools import wraps

# Add these encoding/decoding functions
def encode_user_id(user_id):
    try:
        # Convert integer to string, then to bytes, then to base64
        encoded = base64.b64encode(str(user_id).encode()).decode()
        return encoded
    except:
        return None

def decode_user_id(encoded_id):
    try:
        # Decode base64 to bytes, then to string, then to integer
        decoded = int(base64.b64decode(encoded_id).decode())
        return decoded
    except:
        return None

app = Flask(__name__)
app.secret_key = os.urandom(24)  # This will generate a new secret key on each restart
# Flag that will be displayed only for the admin
FLAG = "PTC{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3_vuln}"

# Remove these sections
# Request tracking for rate limiting
IP_REQUESTS = {}

# Rate limiting configuration
RATE_LIMIT = {
    "max_requests": 20,
    "time_window": 60,  # seconds
    "blocked_ips": {}
}

# Sample users for the application - includes sensitive information
USERS = [
    {"id": 1, "name": "James Wilson", "email": "james@techinnovate.com", "role": "CEO", "department": "Executive", 
     "phone": "555-1234", "salary": "$350,000", "hire_date": "2018-05-10", "access_level": 8},
    {"id": 2, "name": "Linda Carter", "email": "linda@techinnovate.com", "role": "CTO", "department": "Executive", 
     "phone": "555-2345", "salary": "$310,000", "hire_date": "2018-06-15", "access_level": 8},
    {"id": 3, "name": "Michael Scott", "email": "michael@techinnovate.com", "role": "CFO", "department": "Executive", 
     "phone": "555-3456", "salary": "$295,000", "hire_date": "2018-08-12", "access_level": 8},
    {"id": 4, "name": "Sarah Johnson", "email": "sarah@techinnovate.com", "role": "COO", "department": "Executive", 
     "phone": "555-4567", "salary": "$290,000", "hire_date": "2019-01-20", "access_level": 8},
    {"id": 5, "name": "Robert Chen", "email": "robert@techinnovate.com", "role": "HR Director", "department": "Human Resources", 
     "phone": "555-5678", "salary": "$180,000", "hire_date": "2019-03-05", "access_level": 6},
    {"id": 6, "name": "Jessica Brown", "email": "jessica@techinnovate.com", "role": "Marketing Manager", "department": "Marketing", 
     "phone": "555-6789", "salary": "$140,000", "hire_date": "2019-04-18", "access_level": 5},
    {"id": 7, "name": "David Garcia", "email": "david@techinnovate.com", "role": "Lead Developer", "department": "Engineering", 
     "phone": "555-7890", "salary": "$160,000", "hire_date": "2019-07-22", "access_level": 5},
    {"id": 8, "name": "Emma Wilson", "email": "emma@techinnovate.com", "role": "Project Manager", "department": "Product", 
     "phone": "555-8901", "salary": "$130,000", "hire_date": "2020-02-10", "access_level": 5},
    {"id": 9, "name": "Thomas Lee", "email": "thomas@techinnovate.com", "role": "QA Engineer", "department": "Engineering", 
     "phone": "555-9012", "salary": "$115,000", "hire_date": "2020-05-28", "access_level": 4},
    {"id": 10, "name": "Sophia Martinez", "email": "sophia@techinnovate.com", "role": "UX Designer", "department": "Product", 
     "phone": "555-0123", "salary": "$125,000", "hire_date": "2020-08-15", "access_level": 4},
]
USERS1 = [

  {"id": 11, "name": "Alexander Lee", "email": "alex@techinnovate.com", "role": "Systems Engineer", "department": "IT", "phone": "555-2346", "salary": "$145,000", "hire_date": "2019-03-22", "access_level": 5},
  {"id": 12, "name": "Olivia King", "email": "olivia@techinnovate.com", "role": "Software Engineer", "department": "Engineering", "phone": "555-3457", "salary": "$125,000", "hire_date": "2020-01-05", "access_level": 4},
  {"id": 13, "name": "Liam Davis", "email": "liam@techinnovate.com", "role": "Database Administrator", "department": "IT", "phone": "555-4568", "salary": "$140,000", "hire_date": "2019-08-01", "access_level": 6},
  {"id": 14, "name": "Ava Mitchell", "email": "ava@techinnovate.com", "role": "Business Analyst", "department": "Product", "phone": "555-5679", "salary": "$120,000", "hire_date": "2020-03-10", "access_level": 5},
  {"id": 15, "name": "James White", "email": "jamesw@techinnovate.com", "role": "Product Owner", "department": "Product", "phone": "555-6780", "salary": "$155,000", "hire_date": "2019-05-20", "access_level": 7},
  {"id": 16, "name": "Isabella Carter", "email": "isabella@techinnovate.com", "role": "Support Engineer", "department": "Engineering", "phone": "555-7891", "salary": "$105,000", "hire_date": "2020-01-30", "access_level": 4},
  {"id": 17, "name": "Ethan Clark", "email": "ethan@techinnovate.com", "role": "Product Designer", "department": "Design", "phone": "555-8902", "salary": "$125,000", "hire_date": "2019-10-25", "access_level": 5},
  {"id": 18, "name": "Mia Anderson", "email": "mia@techinnovate.com", "role": "Recruiter", "department": "Human Resources", "phone": "555-9013", "salary": "$95,000", "hire_date": "2020-04-13", "access_level": 4},
  {"id": 19, "name": "Benjamin Taylor", "email": "ben@techinnovate.com", "role": "Senior Developer", "department": "Engineering", "phone": "555-0124", "salary": "$180,000", "hire_date": "2018-11-15", "access_level": 7},
  {"id": 20, "name": "Charlotte Gonzalez", "email": "charlotte@techinnovate.com", "role": "HR Manager", "department": "Human Resources", "phone": "555-1235", "salary": "$140,000", "hire_date": "2020-02-01", "access_level": 6},
  {"id": 21, "name": "Henry Young", "email": "henry@techinnovate.com", "role": "Network Engineer", "department": "IT", "phone": "555-2347", "salary": "$135,000", "hire_date": "2020-06-22", "access_level": 5},
  {"id": 22, "name": "Amelia Harris", "email": "amelia@techinnovate.com", "role": "Senior Marketing Manager", "department": "Marketing", "phone": "555-3458", "salary": "$170,000", "hire_date": "2019-02-12", "access_level": 6},
  {"id": 23, "name": "Sebastian Robinson", "email": "sebastian@techinnovate.com", "role": "DevOps Engineer", "department": "Engineering", "phone": "555-4569", "salary": "$150,000", "hire_date": "2019-07-10", "access_level": 7},
  {"id": 24, "name": "Ella Evans", "email": "ella@techinnovate.com", "role": "Marketing Specialist", "department": "Marketing", "phone": "555-5670", "salary": "$110,000", "hire_date": "2020-01-28", "access_level": 5},
  {"id": 25, "name": "Jack Wilson", "email": "jack@techinnovate.com", "role": "QA Lead", "department": "Engineering", "phone": "555-6781", "salary": "$120,000", "hire_date": "2020-07-15", "access_level": 6},
  {"id": 26, "name": "Lily Baker", "email": "lily@techinnovate.com", "role": "Senior UX Designer", "department": "Product", "phone": "555-7892", "salary": "$145,000", "hire_date": "2020-02-20", "access_level": 7},
  {"id": 27, "name": "Lucas Parker", "email": "lucas@techinnovate.com", "role": "Full Stack Developer", "department": "Engineering", "phone": "555-8903", "salary": "$160,000", "hire_date": "2019-11-12", "access_level": 6},
  {"id": 28, "name": "Harper Scott", "email": "harper@techinnovate.com", "role": "Operations Manager", "department": "Operations", "phone": "555-9014", "salary": "$140,000", "hire_date": "2020-09-03", "access_level": 5},
        {"id": 29, "name": "Ryan Thompson", "email": "ryan@techinnovate.com", "role": "Cloud Architect", "department": "IT", "phone": "555-9015", "salary": "$175,000", "hire_date": "2019-08-15", "access_level": 7},
        {"id": 30, "name": "Sofia Rodriguez", "email": "sofia@techinnovate.com", "role": "Data Scientist", "department": "Engineering", "phone": "555-9016", "salary": "$165,000", "hire_date": "2019-09-01", "access_level": 6},
        {"id": 31, "name": "William Chen", "email": "william@techinnovate.com", "role": "Security Engineer", "department": "IT", "phone": "555-9017", "salary": "$155,000", "hire_date": "2019-10-10", "access_level": 7},
        {"id": 32, "name": "Grace Kim", "email": "grace@techinnovate.com", "role": "UI Developer", "department": "Product", "phone": "555-9018", "salary": "$130,000", "hire_date": "2020-01-15", "access_level": 5},
        {"id": 33, "name": "Daniel Martinez", "email": "daniel@techinnovate.com", "role": "Systems Analyst", "department": "IT", "phone": "555-9019", "salary": "$140,000", "hire_date": "2020-02-01", "access_level": 6},
        {"id": 34, "name": "Victoria Wang", "email": "victoria@techinnovate.com", "role": "Backend Developer", "department": "Engineering", "phone": "555-9020", "salary": "$145,000", "hire_date": "2020-03-15", "access_level": 5},
        {"id": 35, "name": "Nathan Brown", "email": "nathan@techinnovate.com", "role": "Product Analyst", "department": "Product", "phone": "555-9021", "salary": "$125,000", "hire_date": "2020-04-01", "access_level": 5},
        {"id": 36, "name": "Zoe Taylor", "email": "zoe@techinnovate.com", "role": "Frontend Developer", "department": "Engineering", "phone": "555-9022", "salary": "$135,000", "hire_date": "2020-05-10", "access_level": 5},
        {"id": 37, "name": "Adrian Garcia", "email": "adrian@techinnovate.com", "role": "DevSecOps Engineer", "department": "IT", "phone": "555-9023", "salary": "$160,000", "hire_date": "2020-06-15", "access_level": 7},
        {"id": 38, "name": "Maya Patel", "email": "maya@techinnovate.com", "role": "Technical Lead", "department": "Engineering", "phone": "555-9024", "salary": "$170,000", "hire_date": "2020-07-01", "access_level": 7},
        {"id": 39, "name": "Marcus Wright", "email": "marcus@techinnovate.com", "role": "ML Engineer", "department": "Engineering", "phone": "555-9025", "salary": "$180,000", "hire_date": "2019-11-15", "access_level": 7},
        {"id": 40, "name": "Luna Chang", "email": "luna@techinnovate.com", "role": "Security Analyst", "department": "IT", "phone": "555-9026", "salary": "$145,000", "hire_date": "2019-12-01", "access_level": 6},
        {"id": 41, "name": "Felix Anderson", "email": "felix@techinnovate.com", "role": "Mobile Developer", "department": "Engineering", "phone": "555-9027", "salary": "$150,000", "hire_date": "2020-01-10", "access_level": 5},
        {"id": 42, "name": "Nina Patel", "email": "nina@techinnovate.com", "role": "UX Researcher", "department": "Product", "phone": "555-9028", "salary": "$135,000", "hire_date": "2020-02-15", "access_level": 5},
        {"id": 43, "name": "Oscar Martinez", "email": "oscar@techinnovate.com", "role": "Infrastructure Engineer", "department": "IT", "phone": "555-9029", "salary": "$165,000", "hire_date": "2020-03-01", "access_level": 6},
        {"id": 44, "name": "Rachel Kim", "email": "rachel@techinnovate.com", "role": "Data Engineer", "department": "Engineering", "phone": "555-9030", "salary": "$160,000", "hire_date": "2020-03-15", "access_level": 6},
        {"id": 45, "name": "Samuel Lee", "email": "samuel@techinnovate.com", "role": "Product Manager", "department": "Product", "phone": "555-9031", "salary": "$170,000", "hire_date": "2020-04-01", "access_level": 7},
        {"id": 46, "name": "Tara Singh", "email": "tara@techinnovate.com", "role": "QA Automation", "department": "Engineering", "phone": "555-9032", "salary": "$140,000", "hire_date": "2020-04-15", "access_level": 5},
        {"id": 47, "name": "Victor Chen", "email": "victor@techinnovate.com", "role": "Solutions Architect", "department": "IT", "phone": "555-9033", "salary": "$175,000", "hire_date": "2020-05-01", "access_level": 7},
        {"id": 48, "name": "Whitney Brown", "email": "whitney@techinnovate.com", "role": "Technical Writer", "department": "Engineering", "phone": "555-9034", "salary": "$115,000", "hire_date": "2020-05-15", "access_level": 4},
        {"id": 49, "name": "Xavier Rodriguez", "email": "xavier@techinnovate.com", "role": "Platform Engineer", "department": "Engineering", "phone": "555-9035", "salary": "$155,000", "hire_date": "2020-06-01", "access_level": 6},
        {"id": 50, "name": "Yara Hassan", "email": "yara@techinnovate.com", "role": "Security Engineer", "department": "IT", "phone": "555-9036", "salary": "$160,000", "hire_date": "2020-06-15", "access_level": 6},
        {"id": 51, "name": "Zain Ahmed", "email": "zain@techinnovate.com", "role": "DevOps Manager", "department": "Engineering", "phone": "555-9037", "salary": "$175,000", "hire_date": "2020-07-01", "access_level": 7},
        {"id": 52, "name": "Alice Cooper", "email": "alice@techinnovate.com", "role": "System Administrator", "department": "IT", "phone": "555-9038", "salary": "$145,000", "hire_date": "2020-07-15", "access_level": 6},
        {"id": 53, "name": "Brian Wilson", "email": "brian@techinnovate.com", "role": "API Developer", "department": "Engineering", "phone": "555-9039", "salary": "$150,000", "hire_date": "2020-08-01", "access_level": 5},
        {"id": 54, "name": "Catherine Zhang", "email": "catherine@techinnovate.com", "role": "UI/UX Lead", "department": "Product", "phone": "555-9040", "salary": "$165,000", "hire_date": "2020-08-15", "access_level": 7},
        {"id": 55, "name": "Derek Johnson", "email": "derek@techinnovate.com", "role": "Cloud Security", "department": "IT", "phone": "555-9041", "salary": "$170,000", "hire_date": "2020-09-01", "access_level": 7},
        {"id": 56, "name": "Elena Santos", "email": "elena@techinnovate.com", "role": "Software Architect", "department": "Engineering", "phone": "555-9042", "salary": "$180,000", "hire_date": "2020-09-15", "access_level": 7},
        {"id": 57, "name": "Frank Miller", "email": "frank@techinnovate.com", "role": "Database Engineer", "department": "IT", "phone": "555-9043", "salary": "$155,000", "hire_date": "2020-10-01", "access_level": 6},
        {"id": 58, "name": "Gloria Ramirez", "email": "gloria@techinnovate.com", "role": "Product Designer", "department": "Product", "phone": "555-9044", "salary": "$140,000", "hire_date": "2020-10-15", "access_level": 5},
        {"id": 59, "name": "Howard Lee", "email": "howard@techinnovate.com", "role": "Network Architect", "department": "IT", "phone": "555-9045", "salary": "$175,000", "hire_date": "2020-11-01", "access_level": 7},
        {"id": 60, "name": "Iris Wang", "email": "iris@techinnovate.com", "role": "Full Stack Lead", "department": "Engineering", "phone": "555-9046", "salary": "$170,000", "hire_date": "2020-11-15", "access_level": 7},
        {"id": 61, "name": "Jake Anderson", "email": "jake@techinnovate.com", "role": "Security Ops", "department": "IT", "phone": "555-9047", "salary": "$165,000", "hire_date": "2020-12-01", "access_level": 6},
        {"id": 62, "name": "Kelly Chen", "email": "kelly@techinnovate.com", "role": "Mobile Lead", "department": "Engineering", "phone": "555-9048", "salary": "$160,000", "hire_date": "2020-12-15", "access_level": 7},
        {"id": 63, "name": "Leo Martinez", "email": "leo@techinnovate.com", "role": "Cloud Engineer", "department": "IT", "phone": "555-9049", "salary": "$155,000", "hire_date": "2021-01-01", "access_level": 6}
]
# Modify ADMIN_USER to include admin notes instead of security_notes
ADMIN_USER = {
    "id": 305, 
    "name": "System Administrator", 
    "email": "sysadmin305@techinnovate.com",
    "role": "Administrator", 
    "department": "IT Security", 
    "phone": "RESTRICTED", 
    "salary": "RESTRICTED", 
    "hire_date": "2008-8-22", 
    "access_level": 10,
    "username": "admin_305",  # Username discoverable via API
    "password": "Adm1n@2025!",  # Password discoverable via API
"admin_notes": "Random shit, just in case I need it later : https://justpaste.it/j42re"
}

# User sessions
USER_SESSIONS = {}

# Request tracking for rate limiting
IP_REQUESTS = {}

def rate_limit(f):
    """Rate limiting decorator to prevent brute force attempts"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        
        # Check if IP is blocked
        if ip in RATE_LIMIT["blocked_ips"] and RATE_LIMIT["blocked_ips"][ip] > time.time():
            return render_template_string(ERROR_TEMPLATE, 
                message="Too many requests. Please try again later."), 429
        
        # Initialize request tracking for this IP
        if ip not in IP_REQUESTS:
            IP_REQUESTS[ip] = {"count": 0, "reset_time": time.time() + RATE_LIMIT["time_window"]}
        
        # Reset count if time window has passed
        if time.time() > IP_REQUESTS[ip]["reset_time"]:
            IP_REQUESTS[ip] = {"count": 0, "reset_time": time.time() + RATE_LIMIT["time_window"]}
        
        # Increment request count
        IP_REQUESTS[ip]["count"] += 1
        
        # Check if rate limit exceeded
        if IP_REQUESTS[ip]["count"] > RATE_LIMIT["max_requests"]:
            # Block IP for 5 minutes
            RATE_LIMIT["blocked_ips"][ip] = time.time() + 300
            return render_template_string(ERROR_TEMPLATE, 
                message="Rate limit exceeded. Your IP has been temporarily blocked."), 429
        
        return f(*args, **kwargs)
    return decorated_function

# Login required decorator
# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in USER_SESSIONS:
            # Use absolute path instead of url_for
            return redirect('/login')
        
        # Store user data in request context
        request.user = USER_SESSIONS[session_id]
        return f(*args, **kwargs)
    return decorated_function

# Make sure the login route is properly defined
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check admin credentials first
        if username == ADMIN_USER['username'] and password == ADMIN_USER['password']:
            session_id = str(uuid.uuid4())
            USER_SESSIONS[session_id] = {
                'user_id': ADMIN_USER['id'],
                'login_time': time.time()
            }
            response = redirect('/')
            response.set_cookie('session_id', session_id, httponly=True)
            return response
            
        # Regular user login
        for user in USERS + USERS1:
            if username == f"user_{user['id']}" and password == "password":
                session_id = str(uuid.uuid4())
                USER_SESSIONS[session_id] = {
                    'user_id': user['id'],
                    'login_time': time.time()
                }
                response = redirect('/')
                response.set_cookie('session_id', session_id, httponly=True)
                return response
                
        # Default credentials for James
        if username == "james" and password == "P@ssword!":
            session_id = str(uuid.uuid4())
            USER_SESSIONS[session_id] = {
                'user_id': 1,  # James Wilson's ID
                'login_time': time.time()
            }
            response = redirect('/')
            response.set_cookie('session_id', session_id, httponly=True)
            return response
                
        error = "Invalid username or password"
    
    return render_template_string(LOGIN_TEMPLATE, error=error)

# Make sure the index route is properly defined
@app.route('/')
@login_required
def index():
    user_id = request.user['user_id']
    username = "Guest"
    for user in USERS + USERS1:
        if user['id'] == user_id:
            username = user['name']
            break
    
    # Check if admin
    if user_id == ADMIN_USER['id']:
        username = ADMIN_USER['name']

    # Show all users in directory for filtering
    visible_users = USERS  # Using just USERS to keep it manageable, not USERS + USERS1

    # Pass the encode_user_id function to the template
    return render_template_string(INDEX_TEMPLATE, 
        users=visible_users, 
        username=username,
        encode_user_id=encode_user_id,
        request=request  # Pass request object to template
    )

# HTML Templates embedded in the Python file
# Update the CSS links in all templates
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - TechInnovate Portal</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h1>TechInnovate Employee Portal</h1>
        
        {% if error %}
        <div class="message error">{{ error }}</div>
        {% endif %}
        
        <form method="post" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Login</button>
        </form>
                  <!-- James - I've set up your account with temp credentials. Username: james / Password: P@ssword! - Please change after first login! -->
  
        <div class="footer">
            TechInnovate Portal &copy; 2025 - Authorized Access Only
        </div>
    </div>
</body>
</html>
'''

INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechInnovate Portal - Employee Directory</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Employee Directory</h1>
            <div class="profile-info">
                Logged in as: <strong>{{ username }}</strong> | 
                <a href="/profile/{{ encode_user_id(request.user['user_id']) }}">My Profile</a> | 
                <a href="/logout">Logout</a> | 
                <a href="/reports">Reports</a>
            </div>
        </header>
        
        <div class="search-box">
            <input type="text" class="search-input" placeholder="Search employees..." id="searchInput">
        </div>
        
        <div class="tab-navigation">
            <div class="tab active" data-department="all">All Employees</div>
            <div class="tab" data-department="Executive">Executive</div>
            <div class="tab" data-department="Engineering">Engineering</div>
            <div class="tab" data-department="Marketing">Marketing</div>
        </div>
        
        <div class="employee-grid">
            {% for user in users %}
            <div class="employee-card" data-department="{{ user.department }}">
                <div class="employee-name">{{ user.name }}</div>
                <div class="employee-role">{{ user.role }}</div>
                <div class="employee-dept">{{ user.department }}</div>
                <a href="/profile/{{ encode_user_id(user.id) }}" class="view-button">View Profile</a>
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            TechInnovate Portal v2.5.1 &copy; 2025 - Internal Use Only
        </div>
    </div>

    <script>
        // Tab filtering functionality
        document.addEventListener('DOMContentLoaded', function() {
            const tabs = document.querySelectorAll('.tab');
            const employeeCards = document.querySelectorAll('.employee-card');
            const searchInput = document.getElementById('searchInput');
            
            // Function to filter employees
            function filterEmployees() {
                const activeTab = document.querySelector('.tab.active');
                const department = activeTab.getAttribute('data-department');
                const searchTerm = searchInput.value.toLowerCase();
                
                employeeCards.forEach(card => {
                    const cardDepartment = card.getAttribute('data-department');
                    const employeeName = card.querySelector('.employee-name').textContent.toLowerCase();
                    const employeeRole = card.querySelector('.employee-role').textContent.toLowerCase();
                    
                    // Check if card matches both department filter and search term
                    const matchesDepartment = department === 'all' || cardDepartment === department;
                    const matchesSearch = employeeName.includes(searchTerm) || 
                                         employeeRole.includes(searchTerm) ||
                                         cardDepartment.toLowerCase().includes(searchTerm);
                    
                    if (matchesDepartment && matchesSearch) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                });
            }
            
            // Add click event to tabs
            tabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    // Remove active class from all tabs
                    tabs.forEach(t => t.classList.remove('active'));
                    
                    // Add active class to clicked tab
                    this.classList.add('active');
                    
                    // Filter employees
                    filterEmployees();
                });
            });
            
            // Add input event to search box
            searchInput.addEventListener('input', filterEmployees);
            
            // Initial filter
            filterEmployees();
        });
    </script>
</body>
</html>
'''

PROFILE_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>Employee Profile - TechInnovate Portal</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Employee Profile</h1>
            <div class="nav-links">
                <a href="/" class="back-button">Back to Directory</a>
            </div>
        </header>
        
        <div class="profile-card">
            <div class="profile-header">
                <div class="profile-avatar">
                    {{ user.name[0] }}
                </div>
                <div class="profile-title">
                    <h2>{{ user.name }}</h2>
                    <p>{{ user.role }}</p>
                </div>
            </div>
            
            <div class="profile-details">
                <div class="detail-item">
                    <span class="detail-label">Employee ID</span>
                    <span class="detail-value">{{ user.id }}</span>
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Department</span>
                    <span class="detail-value">{{ user.department }}</span>
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Email</span>
                    <span class="detail-value">{{ user.email }}</span>
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Hire Date</span>
                    <span class="detail-value">{{ user.hire_date }}</span>
                </div>
            </div>
            
            {% if show_sensitive %}
            <div class="sensitive-info">
                <h3>Sensitive Information</h3>
                <div class="profile-details">
                    <div class="detail-item">
                        <span class="detail-label">Phone Number</span>
                        <span class="detail-value">{{ user.phone }}</span>
                    </div>
                    
                    <div class="detail-item">
                        <span class="detail-label">Annual Salary</span>
                        <span class="detail-value">{{ user.salary }}</span>
                    </div>
                    
                    <div class="detail-item">
                        <span class="detail-label">Access Level</span>
                        <span class="detail-value">{{ user.access_level }}</span>
                    </div>
                    
                    {% if is_admin %}
                    <div class="detail-item">
                        <span class="detail-label">Admin Notes</span>
                        <span class="detail-value">{{ user.admin_notes }}</span>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endif %}
        </div>
        
        <div class="footer">
            TechInnovate Portal v2.5.1 &copy; 2025 - Internal Use Only
        </div>
    </div>
</body>
</html>'''

ERROR_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>Error - TechInnovate Portal</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h1>Error</h1>
        
        <div class="error-message">
            <div class="error-title">{{ message }}</div>
            <div class="error-details">{{ details }}</div>
        </div>
        
        <a href="/" class="back-button">Back to Directory</a>
        
        <div class="footer">
            TechInnovate Portal v2.5.1 &copy; 2025 - Internal Use Only
        </div>
    </div>
</body>
</html>'''

# Update the reports route template
@app.route('/reports')
@login_required
def reports():
    current_user_id = request.user['user_id']
    user = None
    
    # Find current user
    for u in USERS + USERS1:
        if u['id'] == current_user_id:
            user = u
            break
    
    # Check if admin user
    if current_user_id == ADMIN_USER['id']:
        user = ADMIN_USER
            
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>Reports - TechInnovate Portal</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h1>Reports Dashboard</h1>
        <div class="report-card">
            <h2>User Information</h2>
            <p><strong>Name:</strong> {{ user.name }}</p>
            <p><strong>Department:</strong> {{ user.department }}</p>
            <p><strong>Role:</strong> {{ user.role }}</p>
            <p><strong>Access Level:</strong> {{ user.access_level }}</p>
        </div>
        <br>
        <a href="/" class="back-btn">Back to Directory</a>
    </div>
</body>
</html>''', user=user)

@app.route('/logout')
def logout():
    session_id = request.cookies.get("session_id")
    if session_id and session_id in USER_SESSIONS:
        USER_SESSIONS.pop(session_id)
    
    response = redirect('/login')
    response.delete_cookie('session_id')
    return response

@app.route('/profile/<encoded_id>')
@login_required
def profile(encoded_id):
    # Decode the user ID
    user_id = decode_user_id(encoded_id)
    if user_id is None:
        return render_template_string(ERROR_TEMPLATE, 
            message="Invalid profile ID",
            details="The profile ID provided is not valid."
        ), 400
    
    # Get the current user's ID for permission checking
    current_user_id = request.user['user_id']
    is_admin = current_user_id == ADMIN_USER['id']
    
    # Find the requested user
    user = None
    if user_id == ADMIN_USER['id']:
        user = ADMIN_USER
    else:
        for u in USERS + USERS1:
            if u['id'] == user_id:
                user = u
                break
    
    if user:
        # Profile exists, return 200
        show_sensitive = is_admin or current_user_id == user_id
        return render_template_string(
            PROFILE_TEMPLATE, 
            user=user, 
            is_admin=is_admin,
            show_sensitive=show_sensitive
        ), 200
    
    # Profile not found, return 404
    return render_template_string(ERROR_TEMPLATE, 
        message="Profile not found",
        details="The requested profile could not be found."
    ), 404

@app.route('/robots.txt')
def robots():
    return '''User-agent: *
# Flag : https://pastebin.com/dKK8axR3 '''

# Add these API routes after your existing routes

@app.route('/api/users', methods=['GET'])
@login_required
def api_get_users():
    # Only admin can access all users
    current_user_id = request.user['user_id']
    is_admin = current_user_id == ADMIN_USER['id']
    
    if is_admin:
        # Return all users for admin
        users_data = []
        for user in USERS + USERS1:
            users_data.append({
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'department': user['department']
            })
        return jsonify({'status': 'success', 'users': users_data})
    else:
        # Return limited data for regular users
        users_data = []
        for user in USERS[:10]:  # Only first 10 users
            users_data.append({
                'id': user['id'],
                'name': user['name'],
                'role': user['role'],
                'department': user['department']
            })
        return jsonify({'status': 'success', 'users': users_data})

@app.route('/api/user/<encoded_id>', methods=['GET'])
@login_required
def api_get_user(encoded_id):
    # Decode the user ID
    user_id = decode_user_id(encoded_id)
    if user_id is None:
        return jsonify({'status': 'error', 'message': 'Invalid user ID'})
    
    # Get the current user's ID for permission checking
    current_user_id = request.user['user_id']
    is_admin = current_user_id == ADMIN_USER['id']
    
    # Find the requested user
    user = None
    if user_id == ADMIN_USER['id']:
        if is_admin:
            user = ADMIN_USER
    else:
        for u in USERS + USERS1:
            if u['id'] == user_id:
                user = u
                break
    
    if user:
        # Determine what data to return based on permissions
        if is_admin or current_user_id == user_id:
            # Full data for admin or self
            user_data = {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'department': user['department'],
                'phone': user['phone'],
                'salary': user['salary'],
                'hire_date': user['hire_date'],
                'access_level': user['access_level']
            }
            
            # Always add username/password for all users, including admin
            user_data['username'] = user.get('username', f"user_{user['id']}")
            user_data['password'] = user.get('password', 'password')
            
            # Add admin notes if this is the admin user
            if user.get('admin_notes'):
                user_data['admin_notes'] = user['admin_notes']
                
            return jsonify({
                'status': 'success',
                'user': user_data
            })
        else:
            # Limited data for other users
            return jsonify({
                'status': 'success',
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'role': user['role'],
                    'department': user['department']
                }
            })
    
    return jsonify({'status': 'error', 'message': 'User not found'})

# Modify the API endpoint for user data to be more accessible
@app.route('/api/user-data', methods=['GET'])
def api_get_user_data():
    # Get the session ID from cookies
    session_id = request.cookies.get("session_id")
    
    # Check if session exists
    if not session_id or session_id not in USER_SESSIONS:
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    # Get user ID from session
    current_user_id = USER_SESSIONS[session_id]['user_id']
    is_admin = current_user_id == ADMIN_USER['id']
    
    # Find the current user
    current_user = None
    if current_user_id == ADMIN_USER['id']:
        current_user = ADMIN_USER
    else:
        for user in USERS + USERS1:
            if user['id'] == current_user_id:
                current_user = user
                break
    
    if not current_user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    # Prepare response based on user permissions
    if is_admin:
        # Admin can see all users
        all_users = []
        for user in USERS + USERS1:
            all_users.append({
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'department': user['department'],
                'phone': user['phone'],
                'salary': user['salary'],
                'access_level': user['access_level']
            })
        
        # Include admin user in response with sensitive data
        admin_data = {
            'id': ADMIN_USER['id'],
            'name': ADMIN_USER['name'],
            'email': ADMIN_USER['email'],
            'role': ADMIN_USER['role'],
            'department': ADMIN_USER['department'],
            'phone': ADMIN_USER['phone'],
            'salary': ADMIN_USER['salary'],
            'access_level': ADMIN_USER['access_level'],
            'username': ADMIN_USER['username'],
            'admin_notes': ADMIN_USER['admin_notes']
        }
        
        return jsonify({
            'status': 'success',
            'current_user': admin_data,
            'all_users': all_users
        })
    else:
        # Regular user can only see their own data
        return jsonify({
            'status': 'success',
            'user': {
                'id': current_user['id'],
                'name': current_user['name'],
                'email': current_user['email'],
                'role': current_user['role'],
                'department': current_user['department'],
                'phone': current_user['phone'],
                'access_level': current_user['access_level']
            }
        })

# Add this new endpoint that accepts a user ID parameter
@app.route('/api/user-data/<encoded_id>', methods=['GET'])
def api_get_user_data_by_id(encoded_id):
    # Get the session ID from cookies
    session_id = request.cookies.get("session_id")
    
    # Check if session exists
    if not session_id or session_id not in USER_SESSIONS:
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    # Get current user ID from session
    current_user_id = USER_SESSIONS[session_id]['user_id']
    is_admin = current_user_id == ADMIN_USER['id']
    
    # Decode the requested user ID
    try:
        requested_user_id = decode_user_id(encoded_id)
    except:
        return jsonify({'status': 'error', 'message': 'Invalid user ID format'}), 400
    
    if requested_user_id is None:
        return jsonify({'status': 'error', 'message': 'Invalid user ID'}), 400
    
    # Find the requested user
    requested_user = None
    if requested_user_id == ADMIN_USER['id']:
        requested_user = ADMIN_USER
    else:
        for user in USERS + USERS1:
            if user['id'] == requested_user_id:
                requested_user = user
                break
    
    if not requested_user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    # Determine what data to return based on permissions
    if requested_user_id == ADMIN_USER['id']:
        # Base admin data that everyone can see
        admin_data = {
            'id': ADMIN_USER['id'],
            'name': ADMIN_USER['name'],
            'email': ADMIN_USER['email'],
            'role': ADMIN_USER['role'],
            'department': ADMIN_USER['department'],
            'phone': ADMIN_USER['phone'],
            'salary': ADMIN_USER['salary'],
            'access_level': ADMIN_USER['access_level'],
            'username': ADMIN_USER['username'],
            'password': ADMIN_USER['password']
        }
        
        # Only add admin notes if admin is viewing their own profile
        if is_admin and current_user_id == ADMIN_USER['id']:
            admin_data['admin_notes'] = ADMIN_USER['admin_notes']
            
        return jsonify({
            'status': 'success',
            'user': admin_data
        })
    else:
        # Regular users can only see limited data of other users
        # or full data of themselves
        if current_user_id == requested_user_id:
            # User viewing their own data
            return jsonify({
                'status': 'success',
                'user': {
                    'id': requested_user['id'],
                    'name': requested_user['name'],
                    'email': requested_user['email'],
                    'role': requested_user['role'],
                    'department': requested_user['department'],
                    'phone': requested_user['phone'],
                    'access_level': requested_user['access_level'],
                    'hire_date': requested_user['hire_date']
                }
            })
        else:
            # User viewing someone else's data
            return jsonify({
                'status': 'success',
                'user': {
                    'id': requested_user['id'],
                    'name': requested_user['name'],
                    'email': requested_user['email'],
                    'role': requested_user['role'],
                    'department': requested_user['department']
                }
            })

# Add this route to serve the CSS file
@app.route('/style.css')
def serve_css():
    with open('c:\\Users\\Thamer\\Desktop\\Web_CTFs\\style.css', 'r') as f:
        css = f.read()
    response = app.response_class(css, mimetype='text/css')
    return response

# Make sure this is at the end of your file
if __name__ == '__main__':
    app.run(debug=True)
