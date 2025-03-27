import streamlit as st
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from streamlit_chat import message
import pandas as pd
from authlib.integrations.requests_client import OAuth2Session
import os


conn = sqlite3.connect("job_portal.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    user_type TEXT CHECK(user_type IN ('admin', 'employer', 'job_seeker'))
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employer TEXT,
    title TEXT,
    description TEXT,
    location TEXT,
    salary TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER,
    applicant TEXT,
    resume TEXT,
    FOREIGN KEY (job_id) REFERENCES jobs(id),
    FOREIGN KEY (applicant) REFERENCES users(username)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()

def register_user(username, password, user_type):
    if user_type == "admin":
        cursor.execute("SELECT COUNT(*) FROM users WHERE user_type = 'admin'")
        if cursor.fetchone()[0] > 0:
            return False  # Only one admin allowed
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    try:
        cursor.execute("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)",
                       (username, hashed_password, user_type))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login_user(username, password):
    cursor.execute("SELECT password, user_type FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user and check_password_hash(user[0], password):
        return user[1]
    return None

def post_job(employer, title, description, location, salary):
    cursor.execute("INSERT INTO jobs (employer, title, description, location, salary) VALUES (?, ?, ?, ?, ?)",
                   (employer, title, description, location, salary))
    conn.commit()

def get_jobs():
    cursor.execute("SELECT * FROM jobs")
    return cursor.fetchall()

def apply_for_job(job_id, applicant, resume):
    cursor.execute("INSERT INTO applications (job_id, applicant, resume) VALUES (?, ?, ?)",
                   (job_id, applicant, resume))
    conn.commit()

def get_applications():
    cursor.execute("SELECT * FROM applications")
    return cursor.fetchall()

def send_message(sender, receiver, message_text):
    cursor.execute("INSERT INTO chat (sender, receiver, message) VALUES (?, ?, ?)",
                   (sender, receiver, message_text))
    conn.commit()

def get_messages(user1, user2):
    cursor.execute("SELECT sender, message FROM chat WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY timestamp", 
                   (user1, user2, user2, user1))
    return cursor.fetchall()

st.title("Pirate Z Job Portal")
menu = ["Home", "Login", "Register", "Post a Job", "View Jobs", "Admin Panel", "Chat", "Apply for Jobs"]
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["username"] = ""
    st.session_state["user_type"] = ""
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.markdown("""
    # Welcome to Pirate Z Job Portal!
    ### Find Your Dream Job or Hire Top Talent!
    - **Job Seekers:** Upload your resume and apply for jobs.
    - **Employers:** Post job listings and find qualified candidates.
    - **Chat System:** Communicate with potential employers or applicants directly.
    
    Get started by signing up or logging in!
    """)

if choice == "Register":
    st.subheader("Register New Account")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    user_type = st.selectbox("User Type", ["job_seeker", "employer"])
    if st.button("Register"):
        if register_user(new_username, new_password, user_type):
            st.success("Registration successful!")
        else:
            st.error("Username already exists or registration failed.")

if choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user_type = login_user(username, password)
        if user_type:
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.session_state["user_type"] = user_type
            st.success(f"Logged in as {user_type}")
        else:
            st.error("Invalid credentials")

if choice == "View Jobs":
    st.subheader("Available Jobs")
    jobs = get_jobs()
    for job in jobs:
        with st.expander(job[2]):
            st.write(f"**Employer:** {job[1]}")
            st.write(f"**Description:** {job[3]}")
            st.write(f"**Location:** {job[4]}")
            st.write(f"**Salary:** {job[5]}")

if choice == "Chat" and st.session_state["logged_in"]:
    st.subheader("Chat")
    receiver = st.text_input("Chat with (username):")
    chat_messages = get_messages(st.session_state["username"], receiver)
    for sender, msg in chat_messages:
        message(msg, is_user=(sender == st.session_state["username"]))
    new_message = st.text_area("Type your message:")
    if st.button("Send") and new_message:
        send_message(st.session_state["username"], receiver, new_message)
        st.rerun()

if choice == "Post a Job" and st.session_state["logged_in"] and st.session_state["user_type"] == "employer":
    st.subheader("Post a New Job")
    title = st.text_input("Job Title")
    description = st.text_area("Job Description")
    location = st.text_input("Location")
    salary = st.text_input("Salary")
    if st.button("Post Job"):
        post_job(st.session_state["username"], title, description, location, salary)
        st.success("Job posted successfully!")

if choice == "Apply for Jobs" and st.session_state["logged_in"] and st.session_state["user_type"] == "job_seeker":
    st.subheader("Apply for Jobs")
    jobs = cursor.execute("SELECT * FROM jobs").fetchall()
    for job in jobs:
        with st.expander(job[2]):
            st.write(f"**Employer:** {job[1]}")
            st.write(f"**Description:** {job[3]}")
            st.write(f"**Location:** {job[4]}")
            st.write(f"**Salary:** {job[5]}")
            uploaded_file = st.file_uploader("Upload Your CV (PDF)", type=["pdf"], key=job[0])
            if uploaded_file and st.button(f"Apply for {job[2]}", key=f"apply_{job[0]}"):
                file_path = f"uploads/{st.session_state['username']}_{job[0]}.pdf"
                os.makedirs("uploads", exist_ok=True)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.read())
                apply_for_job(job[0], st.session_state["username"], file_path)
                st.success("Application submitted successfully!")        

import streamlit as st
import sqlite3
import pandas as pd
import os


conn = sqlite3.connect("job_portal.db")  
cursor = conn.cursor()


def get_all_users():
    return cursor.execute("SELECT * FROM users").fetchall()


def get_all_jobs():
    return cursor.execute("SELECT id, title, employer, description FROM jobs").fetchall()


def get_all_applications():
    return cursor.execute("""
        SELECT applications.id, jobs.title, applications.applicant, applications.resume
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
    """).fetchall()


def delete_user(user_id):
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


def delete_job(job_id):
    cursor.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
    conn.commit()


def delete_application(app_id):
    cursor.execute("DELETE FROM applications WHERE id = ?", (app_id,))
    conn.commit()


if (
    "logged_in" in st.session_state
    and st.session_state["logged_in"]
    and st.session_state["user_type"] == "admin"
):
    st.title("🛠️ Admin Dashboard")

    
    st.subheader("📌 Manage Users")
    users = get_all_users()
    
    if users:
        df_users = pd.DataFrame(users, columns=["ID", "Username", "Password", "User Type"])
        st.dataframe(df_users)

        user_id_to_delete = st.text_input("Enter User ID to Delete:")
        if st.button("🗑️ Delete User"):
            if user_id_to_delete.strip().isdigit():
                delete_user(int(user_id_to_delete))
                st.success(f"✅ User ID {user_id_to_delete} deleted successfully!")
                st.rerun()
            else:
                st.error("⚠️ Please enter a valid numeric User ID.")
    else:
        st.info("No users found.")

    
    st.subheader("📌 Manage Job Listings")
    jobs = get_all_jobs()

    if jobs:
        for job in jobs:
            with st.expander(f"📄 {job[1]} by {job[2]}"):
                st.write(f"**Description:** {job[3]}")
                if st.button(f"🗑️ Delete Job {job[0]}", key=f"del_job_{job[0]}"):
                    delete_job(job[0])
                    st.success("✅ Job deleted successfully!")
                    st.rerun()
    else:
        st.info("No job listings available.")


    st.subheader("📌 Manage Job Applications")
    applications = get_all_applications()

    if applications:
        for app in applications:
            with st.expander(f"📄 {app[2]} applied for {app[1]}"):
                st.write(f"**Applicant:** {app[2]}")

                resume_path = app[3]  # Path stored in database
                
                
                if resume_path and os.path.exists(resume_path):
                    file_extension = os.path.splitext(resume_path)[-1]  
                    mime_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if file_extension == ".docx" else "application/pdf"

                    with open(resume_path, "rb") as file:
                        st.download_button(
                            "📥 Download CV",
                            data=file,
                            file_name=f"{app[2]}_CV{file_extension}",
                            mime=mime_type
                        )
                else:
                    st.warning(f"⚠️ Resume file not found: {resume_path}")

                if st.button(f"🗑️ Delete Application {app[0]}", key=f"del_app_{app[0]}"):
                    delete_application(app[0])
                    st.success("✅ Application deleted successfully!")
                    st.rerun()
    else:
        st.info("No job applications found.")
