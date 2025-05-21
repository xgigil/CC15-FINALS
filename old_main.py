import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QMainWindow,
    QVBoxLayout, QHBoxLayout, QGridLayout, QMessageBox, QComboBox,
    QInputDialog, QTableWidget, QTableWidgetItem, QDialog, QFormLayout,
    QScrollArea, QStackedWidget
)
from PyQt6.QtCore import Qt
import mysql.connector
from mysql.connector import Error
import bcrypt
from datetime import datetime
from config import verify_role_password

def connect_to_database(parent=None):
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Looking@11072004",
            database="users"
        )
        if connection.is_connected():
            return connection
    except Error as e:
        if parent:
            QMessageBox.critical(parent, "Error", f"Error connecting to database: {e}")
        return None

def execute_query(parent, query, params=None):
    connection = connect_to_database(parent)
    if connection:
        try:
            cursor = connection.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            connection.commit()
            return True
        except Error as e:
            QMessageBox.critical(parent, "Error", f"Database error: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    return False

# --- Welcome Window ---
class WelcomeWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Organization Profiling System")
        self.setGeometry(100, 100, 400, 200)

        layout = QVBoxLayout()

        title = QLabel("Welcome to the Organization Profiling System")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        button_layout = QHBoxLayout()

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.login)
        button_layout.addWidget(login_button)

        register_button = QPushButton("Register")
        register_button.clicked.connect(self.open_register_window)
        button_layout.addWidget(register_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def login(self):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                username = self.username_input.text()
                password = self.password_input.text()

                # Check account exists and get credentials
                query = """SELECT a.user_id, a.password, a.role, a.status
                      FROM accounts a
                      JOIN profiles p ON a.user_id = p.user_id
                      WHERE a.username = %s"""
                cursor.execute(query, (username,))
                result = cursor.fetchone()

                if not result:
                    QMessageBox.warning(self, "Login Failed", "Invalid username or password.")
                    return

                user_id, stored_hash, role, status = result
                
                if status == 'Pending':
                    QMessageBox.warning(self, "Login Failed", 
                        "Account is pending approval. Please wait for executive or administrator confirmation.")
                    return
                
                if status == 'Inactive':
                    QMessageBox.warning(self, "Login Failed", 
                        "Account has been set as inactive. Please contact executive or administrator for more details.")
                    return

                # Verify password
                if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
                    QMessageBox.warning(self, "Login Failed", "Invalid username or password.")
                    return

                # Update last login
                update_query = """UPDATE accounts 
                                SET last_login = CURRENT_TIMESTAMP 
                                WHERE user_id = %s"""
                cursor.execute(update_query, (user_id,))
                connection.commit()

                # Create appropriate dashboard
                try:
                    if role == "Admin":
                        self.dashboard = AdminDashboard(username)
                    elif role == "Executive":
                        self.dashboard = ExecutiveDashboard(username)
                    elif role == "Member":
                        self.dashboard = MemberDashboard(username)
                    else:
                        raise ValueError(f"Unknown role: {role}")
                    
                    self.dashboard.show()
                    self.hide()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Error creating window: {str(e)}")

            finally:
                cursor.close()
                connection.close()
                
    def open_register_window(self):
        self.register_window = RegisterWindow(self)
        self.register_window.show()
        self.hide()

# --- Register Window ---
class RegisterWindow(QWidget):
    def __init__(self, welcome_window):
        super().__init__()
        self.welcome_window = welcome_window
        self.setWindowTitle("Register")
        self.setGeometry(100, 100, 400, 400)

        layout = QGridLayout()

        self.first_name = QLineEdit()
        self.first_name.setPlaceholderText("First Name (All Caps)")
        layout.addWidget(self.first_name, 0, 0, 1, 2)

        self.middle_name = QLineEdit()
        self.middle_name.setPlaceholderText("Middle Name (All Caps)")
        layout.addWidget(self.middle_name, 1, 0, 1, 2)

        self.last_name = QLineEdit()
        self.last_name.setPlaceholderText("Last Name (All Caps)")
        layout.addWidget(self.last_name, 2, 0, 1, 2)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        layout.addWidget(self.username, 3, 0, 1, 2)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password, 4, 0, 1, 2)

        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("Confirm Password")
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_password, 5, 0, 1, 2)

        self.role_box = QComboBox()
        self.role_box.addItems(["Member", "Executive", "Admin"])
        layout.addWidget(self.role_box, 6, 0, 1, 2)

        register_btn = QPushButton("Register")
        register_btn.clicked.connect(self.register_account)
        layout.addWidget(register_btn, 7, 0)

        back_btn = QPushButton("Back")
        back_btn.clicked.connect(self.go_back)
        layout.addWidget(back_btn, 7, 1)

        self.setLayout(layout)

    def register_account(self):
        fn = self.first_name.text()
        mn = self.middle_name.text()
        ln = self.last_name.text()
        un = self.username.text()
        pw = self.password.text()
        cpw = self.confirm_password.text()
        role = self.role_box.currentText()

        # Validation checks
        if not (fn.isupper() and mn.isupper() and ln.isupper()):
            QMessageBox.warning(self, "Invalid Input", "Names must be in ALL CAPS!")
            return

        if pw != cpw:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return

        # Role password verification
        input_password, ok = QInputDialog.getText(self, "Role Password",
                                                f"Enter {role} role password:",
                                                QLineEdit.EchoMode.Password)
        
        if not ok:
            return
        
        if not verify_role_password(role, input_password):
            QMessageBox.warning(self, "Incorrect Password", "Incorrect role-specific password.")
            return

        # Hash password
        hashed_password = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                # Start transaction
                connection.start_transaction()

                # Insert into accounts table with Pending status
                if role != "Admin":
                    account_query = """INSERT INTO accounts (username, password, role, status) 
                                    VALUES (%s, %s, %s, 'Pending')"""
                    cursor.execute(account_query, (un, hashed_password, role))
                    user_id = cursor.lastrowid
                else:
                    account_query = """INSERT INTO accounts (username, password, role, status) 
                                    VALUES (%s, %s, %s, 'Active')"""
                    cursor.execute(account_query, (un, hashed_password, role))
                    user_id = cursor.lastrowid

                    # Insert into profiles table - removed status field
                    profile_query = """INSERT INTO profiles 
                        (user_id, first_name, middle_name, last_name) 
                        VALUES (%s, %s, %s, %s)"""
                    cursor.execute(profile_query, (user_id, fn, mn, ln))

                # Create confirmation request for non-admin accounts
                if role != "Admin":
                    request_query = """INSERT INTO confirmation_requests 
                        (user_id, request_type, requested_by, status) 
                        VALUES (%s, 'Registration', %s, 'Pending')"""
                    cursor.execute(request_query, (user_id, user_id))

                connection.commit()
                QMessageBox.information(self, "Success", 
                    "Registration complete! Waiting for approval." if role != "Admin" 
                    else "Registration complete!")
                self.go_back()

            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Registration error: {str(e)}")
            finally:
                cursor.close()
                connection.close()
                
    def go_back(self):
        self.welcome_window.show()
        self.close()

class BaseDashboard(QMainWindow):
    def __init__(self, username, role):
        super().__init__()
        self.username = username
        self.role = role
        self.user_id = self.get_user_id()
        
    def setup_main_area(self):
        """Setup the main content area below menu bar"""
        self.main_content = QStackedWidget()
        self.setCentralWidget(self.main_content)
        
        # Create default welcome page
        welcome_page = QWidget()
        welcome_layout = QVBoxLayout()
        welcome_label = QLabel(f"Welcome {self.role} {self.username}")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_layout.addWidget(welcome_label)
        welcome_page.setLayout(welcome_layout)
        
        self.main_content.addWidget(welcome_page)

    def show_table_in_main(self, table_widget, title):
        """Display a table in the main content area"""
        page = QWidget()
        layout = QVBoxLayout()
        
        # Add title and back button
        header_layout = QHBoxLayout()
        title_label = QLabel(title)
        back_btn = QPushButton("Back to Dashboard")
        back_btn.clicked.connect(lambda: self.main_content.setCurrentIndex(0))
        header_layout.addWidget(title_label)
        header_layout.addWidget(back_btn)
        layout.addLayout(header_layout)
        
        # Add table
        layout.addWidget(table_widget)
        page.setLayout(layout)
        
        self.main_content.addWidget(page)
        self.main_content.setCurrentWidget(page)

    def get_user_id(self):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                query = "SELECT user_id FROM accounts WHERE username = %s"
                cursor.execute(query, (self.username,))
                result = cursor.fetchone()
                return result[0] if result else None
            finally:
                cursor.close()
                connection.close()

    def logout(self):
        self.welcome_window = WelcomeWindow()
        self.welcome_window.show()
        self.close()

    def view_profile(self):
        profile_window = QDialog(self)
        profile_window.setWindowTitle("Profile View")
        profile_window.setGeometry(150, 150, 500, 400)
        layout = QVBoxLayout()

        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                query = """
                    SELECT p.*, a.username, a.role 
                    FROM profiles p
                    JOIN accounts a ON p.user_id = a.user_id
                    WHERE a.username = %s
                """
                cursor.execute(query, (self.username,))
                profile = cursor.fetchone()

                if profile:
                    form = QFormLayout()
                    for field, value in profile.items():
                        if field not in ['user_id', 'profile_id']:
                            label = QLabel(str(value))
                            form.addRow(f"{field.replace('_', ' ').title()}:", label)
                    layout.addLayout(form)
            finally:
                cursor.close()
                connection.close()

        profile_window.setLayout(layout)
        profile_window.exec()

    def edit_account(self, profile_id):
        edit_window = QDialog(self)
        edit_window.setWindowTitle("Edit Account")
        layout = QFormLayout()

        # Get current account data
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                query = """
                    SELECT a.username, a.password, p.user_id
                    FROM accounts a
                    JOIN profiles p ON a.user_id = p.user_id
                    WHERE p.profile_id = %s
                """
                cursor.execute(query, (profile_id,))
                account = cursor.fetchone()

                if account:
                    # Username field
                    username_input = QLineEdit(account['username'])
                    layout.addRow("Username:", username_input)

                    #New username field


                    # Current password field
                    current_password = QLineEdit()
                    current_password.setEchoMode(QLineEdit.EchoMode.Password)
                    current_password.setPlaceholderText("Enter current password")
                    layout.addRow("Current Password:", current_password)

                    # New password fields
                    new_password = QLineEdit()
                    new_password.setEchoMode(QLineEdit.EchoMode.Password)
                    new_password.setPlaceholderText("Leave blank to keep current password")
                    layout.addRow("New Password:", new_password)

                    confirm_password = QLineEdit()
                    confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
                    confirm_password.setPlaceholderText("Confirm new password")
                    layout.addRow("Confirm Password:", confirm_password)

                    def save_account_changes():
                        # Verify current password
                        if not bcrypt.checkpw(current_password.text().encode(), 
                                            account['password'].encode()):
                            QMessageBox.warning(edit_window, "Error", 
                                            "Current password is incorrect!")
                            return

                        # Check if new passwords match
                        if new_password.text() != confirm_password.text():
                            QMessageBox.warning(edit_window, "Error", 
                                            "New passwords do not match!")
                            return

                        try:
                            connection = connect_to_database(self)
                            cursor = connection.cursor()
                            
                            # Update username if changed
                            if username_input.text() != account['username']:
                                # Check if username already exists
                                cursor.execute("SELECT user_id FROM accounts WHERE username = %s", 
                                            (username_input.text(),))
                                if cursor.fetchone():
                                    QMessageBox.warning(edit_window, "Error", 
                                                    "Username already exists!")
                                    return
                                
                                cursor.execute("UPDATE accounts SET username = %s WHERE user_id = %s",
                                            (username_input.text(), account['user_id']))

                            # Update password if provided
                            if new_password.text():
                                hashed_password = bcrypt.hashpw(
                                    new_password.text().encode(), bcrypt.gensalt())
                                cursor.execute("UPDATE accounts SET password = %s WHERE user_id = %s",
                                            (hashed_password, account['user_id']))

                            connection.commit()
                            QMessageBox.information(edit_window, "Success", 
                                                "Account updated successfully!")
                            edit_window.accept()

                            self.logout()

                        except mysql.connector.Error as e:
                            QMessageBox.critical(edit_window, "Error", 
                                            f"Database error: {str(e)}")
                        finally:
                            if connection:
                                connection.close()

                    # Save button
                    save_btn = QPushButton("Save Changes")
                    save_btn.clicked.connect(save_account_changes)
                    layout.addWidget(save_btn)

            finally:
                cursor.close()
                connection.close()

        edit_window.setLayout(layout)
        edit_window.exec()

    def edit_information(self, profile_id):
        edit_window = QDialog(self)
        edit_window.setWindowTitle("Edit Information")
        layout = QFormLayout()

        # Get current profile data
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                query = """
                    SELECT *
                    FROM profiles
                    WHERE profile_id = %s
                """
                cursor.execute(query, (profile_id,))
                profile = cursor.fetchone()

                if profile:
                    # Create input fields
                    fields = {
                        'first_name': QLineEdit(profile['first_name']),
                        'middle_name': QLineEdit(profile['middle_name']),
                        'last_name': QLineEdit(profile['last_name']),
                        'email': QLineEdit(profile.get('email', '')),
                        'contact_number': QLineEdit(profile.get('contact_number', '')),
                        'department': QLineEdit(profile.get('department', '')),
                        'position': QLineEdit(profile.get('position', ''))
                    }

                    # Add fields to layout
                    for key, field in fields.items():
                        layout.addRow(f"{key.replace('_', ' ').title()}:", field)

                    def save_information_changes():
                        try:
                            connection = connect_to_database(self)
                            cursor = connection.cursor()
                            
                            # Update profile information
                            query = """
                                UPDATE profiles 
                                SET first_name = %s, middle_name = %s, last_name = %s,
                                    email = %s, contact_number = %s, department = %s,
                                    position = %s
                                WHERE profile_id = %s
                            """
                            cursor.execute(query, (
                                fields['first_name'].text().upper(),
                                fields['middle_name'].text().upper(),
                                fields['last_name'].text().upper(),
                                fields['email'].text(),
                                fields['contact_number'].text(),
                                fields['department'].text(),
                                fields['position'].text(),
                                profile_id
                            ))
                            
                            connection.commit()
                            QMessageBox.information(edit_window, "Success", 
                                                "Information updated successfully!")
                            edit_window.accept()

                        except mysql.connector.Error as e:
                            QMessageBox.critical(edit_window, "Error", f"Database error: {str(e)}")
                        finally:
                            if connection:
                                connection.close()

                    # Save button
                    save_btn = QPushButton("Save Changes")
                    save_btn.clicked.connect(save_information_changes)
                    layout.addWidget(save_btn)

            finally:
                cursor.close()
                connection.close()

        edit_window.setLayout(layout)
        edit_window.exec()

    def save_profile_changes(self, profile_id, fields):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                query = """UPDATE profiles 
                          SET first_name = %s, middle_name = %s, last_name = %s
                          WHERE profile_id = %s"""
                cursor.execute(query, (
                    fields['first_name'].text().upper(),
                    fields['middle_name'].text().upper(),
                    fields['last_name'].text().upper(),
                    profile_id
                ))
                connection.commit()
                QMessageBox.information(self, "Success", "Profile updated successfully")
            finally:
                cursor.close()
                connection.close()
                
    def get_profile_id(self):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                query = """
                    SELECT profile_id 
                    FROM profiles 
                    WHERE user_id = (
                        SELECT user_id 
                        FROM accounts 
                        WHERE username = %s
                    )
                """
                cursor.execute(query, (self.username,))
                result = cursor.fetchone()
                return result[0] if result else None
            finally:
                cursor.close()
                connection.close()

    def view_active_users(self):
        # Create container widget for search and table
        container = QWidget()
        layout = QVBoxLayout(container)

        # Add search functionality
        search_layout = QHBoxLayout()
        search_input = QLineEdit()
        search_input.setPlaceholderText("Search by name or username...")
        search_btn = QPushButton("Search")
        search_layout.addWidget(search_input)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)

        # Create table
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Name", "Username", "Role", "Status"])

        def load_users(search_term=""):
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        SELECT p.first_name, p.middle_name, p.last_name,
                            a.username, a.role, a.status
                        FROM profiles p
                        JOIN accounts a ON p.user_id = a.user_id
                        WHERE a.status = 'Active'
                        AND a.role != 'Admin'
                        AND (
                            CONCAT(p.first_name, ' ', p.middle_name, ' ', p.last_name) LIKE %s
                            OR a.username LIKE %s
                        )
                        ORDER BY p.last_name, p.first_name
                    """
                    search_pattern = f"%{search_term}%" if search_term else "%"
                    cursor.execute(query, (search_pattern, search_pattern))
                    users = cursor.fetchall()

                    table.setRowCount(len(users))
                    for i, user in enumerate(users):
                        full_name = f"{user[0]} {user[1]} {user[2]}"
                        table.setItem(i, 0, QTableWidgetItem(full_name))
                        table.setItem(i, 1, QTableWidgetItem(user[3]))
                        table.setItem(i, 2, QTableWidgetItem(user[4]))
                        table.setItem(i, 3, QTableWidgetItem(user[5]))

                finally:
                    cursor.close()
                    connection.close()

        # Connect search button and Enter key
        search_btn.clicked.connect(lambda: load_users(search_input.text()))
        search_input.returnPressed.connect(lambda: load_users(search_input.text()))

        # Add table to layout and perform initial load
        layout.addWidget(table)
        load_users()

        # Show in main area
        self.show_table_in_main(container, "Active Users")

    def request_deletion(self):
        reply = QMessageBox.question(
            self, 'Confirm Deletion',
            'Are you sure you want to request account deletion?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """INSERT INTO confirmation_requests 
                        (user_id, request_type, requested_by, status)
                        VALUES (%s, 'Deletion', %s, 'Pending')"""
                    cursor.execute(query, (self.user_id, self.user_id))
                    connection.commit()
                    QMessageBox.information(
                        self, "Success",
                        "Deletion request submitted. Waiting for executive approval.")
                finally:
                    cursor.close()
                    connection.close()
        
class AdminDashboard(BaseDashboard):
    def __init__(self, username):
        super().__init__(username, "Admin")
        self.setup_ui()
        
    def setup_ui(self):
        self.setGeometry(100, 100, 800, 600)
        self.setWindowTitle("Admin Dashboard")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        welcome_label = QLabel(f"Welcome Admin {self.username}")
        layout.addWidget(welcome_label)

        # Create menu bar
        menubar = self.menuBar()

        # Profile Menu
        profile_menu = menubar.addMenu("Profile")
        view_profile = profile_menu.addAction("My Profile")
        view_profile.triggered.connect(self.view_profile)
        
        edit_menu = profile_menu.addMenu("Edit")
        edit_account = edit_menu.addAction("Account Settings")
        edit_account.triggered.connect(lambda: self.edit_account(self.get_profile_id()))
        edit_information = edit_menu.addAction("Personal Information")
        edit_information.triggered.connect(lambda: self.edit_information(self.get_profile_id()))
        
        # Account Management Menu
        account_menu = menubar.addMenu("Account Management")
        create_account = account_menu.addAction("Create Account")
        create_account.triggered.connect(self.create_account)
        pending_reg = account_menu.addAction("Pending Registrations")
        pending_reg.triggered.connect(self.view_pending_registrations)
        deletion_req = account_menu.addAction("Deletion Requests")
        deletion_req.triggered.connect(self.view_deletion_requests)

        # User Management Menu
        user_menu = menubar.addMenu("User Management")
        manage_users = user_menu.addAction("Manage Users")
        manage_users.triggered.connect(self.manage_users)

        # System Menu
        system_menu = menubar.addMenu("System")
        view_logs = system_menu.addAction("View System Logs")
        view_logs.triggered.connect(self.view_logs)

        # Logout Menu
        logout_menu = menubar.addMenu("Account")
        logout_action = logout_menu.addAction("Logout")
        logout_action.triggered.connect(self.logout)
        
        self.setup_main_area()

    def view_logs(self):
        logs_window = QDialog(self)
        logs_window.setWindowTitle("System Logs")
        layout = QVBoxLayout()

        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["Timestamp", "User", "Action", "Details", "Status"])

        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                query = """
                    SELECT l.timestamp, a.username, l.action, l.details, l.status
                    FROM system_logs l
                    LEFT JOIN accounts a ON l.user_id = a.user_id
                    ORDER BY l.timestamp DESC
                    LIMIT 1000
                """
                cursor.execute(query)
                logs = cursor.fetchall()

                table.setRowCount(len(logs))
                for i, log in enumerate(logs):
                    for j, value in enumerate(log):
                        table.setItem(i, j, QTableWidgetItem(str(value)))

            finally:
                cursor.close()
                connection.close()

        layout.addWidget(table)
        logs_window.setLayout(layout)
        logs_window.exec()

    def manage_users(self):
        # Create container widget
        container = QWidget()
        layout = QVBoxLayout(container)

        # Add search functionality
        search_layout = QHBoxLayout()
        search_input = QLineEdit()
        search_input.setPlaceholderText("Search by name or username...")
        search_btn = QPushButton("Search")
        search_layout.addWidget(search_input)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)

        # Create table
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Name", "Username", "Role", "Department", "Position", "Status",
            "Last Login", "Action"
        ])

        def load_users(search_term=""):
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        SELECT p.user_id, p.first_name, p.middle_name, p.last_name,
                            a.username, a.role, p.department, p.position, a.status, 
                            a.last_login
                        FROM profiles p
                        JOIN accounts a ON p.user_id = a.user_id
                        WHERE CONCAT(p.first_name, ' ', p.middle_name, ' ', p.last_name) 
                            LIKE %s
                        OR a.username LIKE %s
                        ORDER BY a.role, a.status, p.last_name
                    """
                    search_pattern = f"%{search_term}%" if search_term else "%"
                    cursor.execute(query, (search_pattern, search_pattern))
                    users = cursor.fetchall()

                    table.setRowCount(len(users))
                    for i, user in enumerate(users):
                        # ... existing table population code ...
                        user_id = user[0]
                        full_name = f"{user[1]} {user[2]} {user[3]}"
                        table.setItem(i, 0, QTableWidgetItem(full_name))
                        table.setItem(i, 1, QTableWidgetItem(user[4]))
                        table.setItem(i, 2, QTableWidgetItem(user[5]))
                        table.setItem(i, 3, QTableWidgetItem(user[6] or "Not Set"))
                        table.setItem(i, 4, QTableWidgetItem(user[7] or "Not Set"))
                        table.setItem(i, 5, QTableWidgetItem(user[8]))
                        table.setItem(i, 6, QTableWidgetItem(str(user[9]) if user[9] else "Never"))

                        # Action buttons
                        action_widget = QWidget()
                        action_layout = QHBoxLayout()
                        action_layout.setContentsMargins(0, 0, 0, 0)

                        edit_btn = QPushButton("Edit")

                        edit_btn.clicked.connect(lambda: self.edit_user(self.get_profile_id()))

                        action_layout.addWidget(edit_btn)
                        action_widget.setLayout(action_layout)
                        table.setCellWidget(i, 7, action_widget)

                finally:
                    cursor.close()
                    connection.close()

        # Connect search button
        search_btn.clicked.connect(lambda: load_users(search_input.text()))

        # Add table to layout
        layout.addWidget(table)

        # Initial load
        load_users()

        # Show in main area
        self.show_table_in_main(container, "Manage Users")
   
    def create_account(self):
        account_window = QDialog(self)
        account_window.setWindowTitle("Create Account")
        layout = QFormLayout()

        # Create input fields
        fields = {
            'username': QLineEdit(),
            'password': QLineEdit(),
            'first_name': QLineEdit(),
            'middle_name': QLineEdit(),
            'last_name': QLineEdit(),
        }
        fields['password'].setEchoMode(QLineEdit.EchoMode.Password)

        role_box = QComboBox()
        role_box.addItems(["Member", "Executive"])

        for key, field in fields.items():
            layout.addRow(f"{key.replace('_', ' ').title()}:", field)
        layout.addRow("Role:", role_box)

        create_btn = QPushButton("Create Account")
        create_btn.clicked.connect(lambda: self.save_new_account(
            fields, role_box.currentText()))
        layout.addWidget(create_btn)

        account_window.setLayout(layout)
        account_window.exec()

    def save_new_account(self, fields, role):
        # Hash password
        hashed_password = bcrypt.hashpw(
            fields['password'].text().encode(), bcrypt.gensalt())

        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()

                # Insert account
                account_query = """INSERT INTO accounts (username, password, role, status)
                                VALUES (%s, %s, %s, 'Active')"""
                cursor.execute(account_query, (
                    fields['username'].text(),
                    hashed_password,
                    role
                ))
                user_id = cursor.lastrowid

                # Insert profile
                profile_query = """INSERT INTO profiles 
                    (user_id, first_name, middle_name, last_name)
                    VALUES (%s, %s, %s, %s)"""
                cursor.execute(profile_query, (
                    user_id,
                    fields['first_name'].text().upper(),
                    fields['middle_name'].text().upper(),
                    fields['last_name'].text().upper()
                ))

                connection.commit()
                QMessageBox.information(self, "Success", "Account created successfully")

            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error creating account: {str(e)}")
            finally:
                cursor.close()
                connection.close()

    def edit_user(self, user_id):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                query = """
                    SELECT p.*, a.username, a.role, a.status
                    FROM profiles p
                    JOIN accounts a ON p.user_id = a.user_id
                    WHERE p.user_id = %s
                """
                cursor.execute(query, (user_id,))
                user = cursor.fetchone()

                if user:
                    edit_window = QDialog(self)
                    edit_window.setWindowTitle(f"Edit User: {user['username']}")
                    layout = QFormLayout()

                    # Username field
                    username_field = QLineEdit(user['username'])
                    layout.addRow("Username:", username_field)

                    # Editable fields for names
                    name_fields = {}
                    for field in ['first_name', 'middle_name', 'last_name']:
                        name_fields[field] = QLineEdit(user[field])
                        layout.addRow(f"{field.replace('_', ' ').title()}:", name_fields[field])

                    # Editable fields for profile data
                    profile_fields = {
                        'department': QLineEdit(user['department'] if user['department'] else ""),
                        'position': QLineEdit(user['position'] if user['position'] else "")
                    }
                    for key, field in profile_fields.items():
                        layout.addRow(f"{key.title()}:", field)

                    # Role dropdown
                    role_box = QComboBox()
                    role_box.addItems(["Member", "Executive", "Admin"])
                    role_box.setCurrentText(user['role'])
                    layout.addRow("Role:", role_box)

                    # Status dropdown
                    status_box = QComboBox()
                    status_box.addItems(["Active", "Inactive"])
                    status_box.setCurrentText(user['status'])
                    layout.addRow("Status:", status_box)

                    # Save button
                    save_btn = QPushButton("Save Changes")
                    save_btn.clicked.connect(lambda: self.save_user_changes(
                        user_id,
                        username_field.text(),
                        name_fields,
                        profile_fields,
                        role_box.currentText(),
                        status_box.currentText()
                    ))
                    layout.addWidget(save_btn)

                    # Reset password button
                    reset_pass_btn = QPushButton("Reset Password")
                    reset_pass_btn.clicked.connect(lambda: self.reset_user_password(user_id))
                    layout.addWidget(reset_pass_btn)

                    # Delete user button
                    delete_btn = QPushButton("Delete User")
                    delete_btn.setStyleSheet("color: red")
                    delete_btn.clicked.connect(lambda: self.delete_user(user_id))
                    layout.addWidget(delete_btn)

                    # Finalize and show dialog
                    edit_window.setLayout(layout)
                    edit_window.exec()

            finally:
                cursor.close()
                connection.close()

    def save_user_changes(self, user_id, username, name_fields, profile_fields, role, status):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()

                # Update profiles table
                profile_query = """
                    UPDATE profiles 
                    SET first_name = %s, middle_name = %s, last_name = %s,
                        department = %s, position = %s
                    WHERE user_id = %s
                """
                cursor.execute(profile_query, (
                    name_fields['first_name'].text().upper(),
                    name_fields['middle_name'].text().upper(),
                    name_fields['last_name'].text().upper(),
                    profile_fields['department'].text().upper(),
                    profile_fields['position'].text().upper(),
                    user_id
                ))

                # Update accounts table
                account_query = """
                    UPDATE accounts 
                    SET username = %s, role = %s, status = %s
                    WHERE user_id = %s
                """
                cursor.execute(account_query, (
                    username,
                    role,
                    status,
                    user_id
                ))

                connection.commit()
                QMessageBox.information(self, "Success", "User updated successfully.")
                self.setup_main_area()

            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error updating user: {str(e)}")
            finally:
                cursor.close()
                connection.close()

    def reset_user_password(self, user_id):
        dialog = QDialog(self)
        dialog.setWindowTitle("Reset Password")
        layout = QFormLayout()

        new_pass = QLineEdit()
        new_pass.setEchoMode(QLineEdit.Password)
        confirm_pass = QLineEdit()
        confirm_pass.setEchoMode(QLineEdit.Password)

        layout.addRow("New Password:", new_pass)
        layout.addRow("Confirm Password:", confirm_pass)

        def apply_reset():
            if new_pass.text() != confirm_pass.text():
                QMessageBox.warning(dialog, "Mismatch", "Passwords do not match.")
                return
            hashed_password = bcrypt.hashpw(new_pass.text().encode(), bcrypt.gensalt())
            connection = connect_to_database(self)
            if connection:
                cursor = connection.cursor()
                cursor.execute("UPDATE accounts SET password = %s WHERE user_id = %s", (hashed_password, user_id))
                connection.commit()
                cursor.close()
                connection.close()
            QMessageBox.information(dialog, "Success", "Password reset successfully.")
            dialog.accept()

        save_btn = QPushButton("Reset")
        save_btn.clicked.connect(apply_reset)
        layout.addWidget(save_btn)

        dialog.setLayout(layout)
        dialog.exec()

    def delete_user(self, user_id):
        reply = QMessageBox.question(
            self, 'Confirm Deletion',
            'Are you sure you want to delete this user? This action cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    connection.start_transaction()

                    # Delete from profiles first (due to foreign key constraint)
                    cursor.execute("DELETE FROM confirmation_requests WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM profiles WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM accounts WHERE user_id = %s", (user_id,))

                    connection.commit()
                    QMessageBox.information(self, "Success", "User deleted successfully")

                except mysql.connector.Error as e:
                    connection.rollback()
                    QMessageBox.critical(self, "Error", f"Error deleting user: {str(e)}")
                finally:
                    cursor.close()
                    connection.close()

    def view_pending_registrations(self):
        # Create container widget
        container = QWidget()
        layout = QVBoxLayout(container)
        
        # Create table
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "Name", "Username", "Role", "Registration Date", "Status", "Actions"
        ])

        def load_registrations():
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        SELECT p.first_name, p.middle_name, p.last_name,
                            a.username, a.role, cr.requested_at, a.status, 
                            cr.request_id, a.user_id
                        FROM confirmation_requests cr
                        JOIN accounts a ON cr.user_id = a.user_id
                        JOIN profiles p ON a.user_id = p.user_id
                        WHERE cr.request_type = 'Registration'
                        AND cr.status = 'Pending'
                        ORDER BY cr.requested_at DESC
                    """
                    cursor.execute(query)
                    registrations = cursor.fetchall()
                    cursor.execute(query)
                    registrations = cursor.fetchall()

                    table.setRowCount(len(registrations))
                    for i, reg in enumerate(registrations):
                        full_name = f"{reg[0]} {reg[1]} {reg[2]}"
                        table.setItem(i, 0, QTableWidgetItem(full_name))
                        table.setItem(i, 1, QTableWidgetItem(reg[3]))
                        table.setItem(i, 2, QTableWidgetItem(reg[4]))
                        table.setItem(i, 3, QTableWidgetItem(str(reg[5])))
                        table.setItem(i, 4, QTableWidgetItem(reg[6]))

                        # Action buttons
                        actions_widget = QWidget()
                        actions_layout = QHBoxLayout()
                        approve_btn = QPushButton("Approve")
                        reject_btn = QPushButton("Reject")

                        approve_btn.clicked.connect(
                            lambda checked, rid=reg[7], uid=reg[8]: 
                            self.approve_registration(rid, uid))
                        reject_btn.clicked.connect(
                            lambda checked, rid=reg[7], uid=reg[8]: 
                            self.reject_registration(rid, uid))

                        actions_layout.addWidget(approve_btn)
                        actions_layout.addWidget(reject_btn)
                        actions_widget.setLayout(actions_layout)
                        table.setCellWidget(i, 5, actions_widget)

                finally:
                    cursor.close()
                    connection.close()

        # Initial load
        load_registrations()
        
        # Add table to layout
        layout.addWidget(table)
        
        # Show in main area
        self.show_table_in_main(container, "Pending Registrations")

    def approve_registration(self, request_id, user_id):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()
                
                # First check if request exists and is pending
                cursor.execute("""
                    SELECT status FROM confirmation_requests 
                    WHERE request_id = %s AND request_type = 'Registration'
                """, (request_id,))
                result = cursor.fetchone()
                
                if not result or result[0] != 'Pending':
                    QMessageBox.warning(self, "Error", "Request no longer valid")
                    return
                
                # Update request status
                cursor.execute("""
                    UPDATE confirmation_requests 
                    SET status = 'Approved'
                    WHERE request_id = %s
                """, (request_id,))
                
                # Add record to confirmation_approvals
                cursor.execute("""
                    INSERT INTO confirmation_approvals 
                    (request_id, approved_by)
                    VALUES (%s, %s)
                """, (request_id, self.user_id))
                
                # Activate user account
                cursor.execute("""
                    UPDATE accounts 
                    SET status = 'Active'
                    WHERE user_id = %s
                """, (user_id,))
                
                connection.commit()
                QMessageBox.information(self, "Success", "Registration approved")
                self.view_pending_registrations()  # Refresh the view
                
            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
            finally:
                cursor.close()
                connection.close()

    def reject_registration(self, request_id, user_id):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()
                
                # First check if request exists and is pending
                cursor.execute("""
                    SELECT status FROM confirmation_requests 
                    WHERE request_id = %s AND request_type = 'Registration'
                    AND status = 'Pending'
                """, (request_id,))
                result = cursor.fetchone()
                
                if not result:
                    QMessageBox.warning(self, "Error", "Request no longer valid")
                    return
                
                # Update confirmation request status
                cursor.execute("""
                    UPDATE confirmation_requests 
                    SET status = 'Rejected'
                    WHERE request_id = %s
                """, (request_id,))
                
                # Add record to confirmation_approvals
                cursor.execute("""
                    INSERT INTO confirmation_approvals 
                    (request_id, approved_by) 
                    VALUES (%s, %s)
                """, (request_id, self.user_id))
                
                # Update account status
                cursor.execute("""
                    UPDATE accounts 
                    SET status = 'Inactive'
                    WHERE user_id = %s
                """, (user_id,))
                
                connection.commit()
                QMessageBox.information(self, "Success", "Registration rejected")
                self.view_pending_registrations()  # Refresh the view
                
            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
            finally:
                cursor.close()
                connection.close()
            
    def view_deletion_requests(self):
        # Create container widget
        container = QWidget()
        layout = QVBoxLayout(container)
        
        # Create table
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels([
            "Name", "Username", "Role", "Request Date", "Actions"
        ])

        def load_requests():
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        SELECT p.first_name, p.middle_name, p.last_name,
                            a.username, a.role, cr.requested_at, a.status, 
                            cr.request_id, a.user_id
                        FROM confirmation_requests cr
                        JOIN accounts a ON cr.user_id = a.user_id
                        JOIN profiles p ON a.user_id = p.user_id
                        WHERE cr.request_type = 'Deletion'
                        AND cr.status = 'Pending'
                        ORDER BY cr.requested_at DESC
                    """
                    cursor.execute(query)
                    requests = cursor.fetchall()
                    cursor.execute(query)
                    requests = cursor.fetchall()

                    table.setRowCount(len(requests))
                    for i, req in enumerate(requests):
                        full_name = f"{req[0]} {req[1]} {req[2]}"
                        table.setItem(i, 0, QTableWidgetItem(full_name))
                        table.setItem(i, 1, QTableWidgetItem(req[3]))
                        table.setItem(i, 2, QTableWidgetItem(req[4]))
                        table.setItem(i, 3, QTableWidgetItem(str(req[5])))

                        # Action buttons
                        actions_widget = QWidget()
                        actions_layout = QHBoxLayout()
                        approve_btn = QPushButton("Approve")
                        reject_btn = QPushButton("Reject")

                        approve_btn.clicked.connect(
                            lambda checked, rid=req[6], uid=req[7]: 
                            self.approve_deletion(rid, uid))
                        reject_btn.clicked.connect(
                            lambda checked, rid=req[6]: 
                            self.reject_deletion(rid))

                        actions_layout.addWidget(approve_btn)
                        actions_layout.addWidget(reject_btn)
                        actions_widget.setLayout(actions_layout)
                        table.setCellWidget(i, 4, actions_widget)

                finally:
                    cursor.close()
                    connection.close()

        # Initial load
        load_requests()
        
        # Add table to layout
        layout.addWidget(table)
        
        # Show in main area
        self.show_table_in_main(container, "Deletion Requests")

    def approve_deletion(self, request_id, user_id):
        reply = QMessageBox.question(self, 'Confirm Approval',
            'Are you sure you want to approve this deletion request?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    connection.start_transaction()
                    
                    # First check if request exists and is pending
                    cursor.execute("""
                        SELECT status FROM confirmation_requests 
                        WHERE request_id = %s AND request_type = 'Deletion'
                    """, (request_id,))
                    result = cursor.fetchone()
                    
                    if not result or result[0] != 'Pending':
                        QMessageBox.warning(self, "Error", "Request no longer valid")
                        return
                    
                    # Delete any related confirmation requests if they exist
                    cursor.execute("""DELETE FROM confirmation_requests 
                        WHERE user_id = %s""", (user_id,))
                    
                    # Delete profile and account
                    cursor.execute("DELETE FROM profiles WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM accounts WHERE user_id = %s", (user_id,))
                    
                    connection.commit()
                    QMessageBox.information(self, "Success", "Deletion request approved")
                    self.view_deletion_requests()  # Refresh the view
                    
                except mysql.connector.Error as e:
                    connection.rollback()
                    QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
                finally:
                    cursor.close()
                    connection.close()

    def reject_deletion(self, request_id):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()
                
                # Update confirmation_requests status
                cursor.execute("""
                    UPDATE confirmation_requests 
                    SET status = 'Rejected'
                    WHERE request_id = %s
                """, (request_id,))
                
                # Add record to confirmation_approvals with correct column name
                cursor.execute("""
                    INSERT INTO confirmation_approvals 
                    (request_id, approved_by) 
                    VALUES (%s, %s)
                """, (request_id, self.user_id))
                
                connection.commit()
                QMessageBox.information(self, "Success", "Deletion request rejected")
                self.view_deletion_requests()  # Refresh the view
                
            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
            finally:
                cursor.close()
                connection.close()


class ExecutiveDashboard(BaseDashboard):
    def __init__(self, username):
        super().__init__(username, "Executive")
        self.setup_ui()
        
    def setup_ui(self):
        self.setGeometry(100, 100, 800, 600)
        self.setWindowTitle("Executive Dashboard")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        welcome_label = QLabel(f"Welcome Executive {self.username}")
        layout.addWidget(welcome_label)

        # Create menu bar
        menubar = self.menuBar()

        # Profile Menu
        profile_menu = menubar.addMenu("Profile")
        view_profile = profile_menu.addAction("My Profile")
        view_profile.triggered.connect(self.view_profile)
        
        edit_menu = profile_menu.addMenu("Edit")
        edit_account = edit_menu.addAction("Account Settings")
        edit_account.triggered.connect(lambda: self.edit_account(self.get_profile_id()))
        edit_information = edit_menu.addAction("Personal Information")
        edit_information.triggered.connect(lambda: self.edit_information(self.get_profile_id()))
        # Account Management Menu
        account_menu = menubar.addMenu("Account Management")
        pending_reg = account_menu.addAction("Pending Registrations")
        pending_reg.triggered.connect(self.view_pending_registrations)
        deletion_req = account_menu.addAction("Deletion Requests")
        deletion_req.triggered.connect(self.view_deletion_requests)

        # User Management Menu
        user_menu = menubar.addMenu("User Management")
        view_users = user_menu.addAction("View Active Users")
        view_users.triggered.connect(self.view_active_users)
        manage_profiles = user_menu.addAction("Manage User Profiles")
        manage_profiles.triggered.connect(self.manage_users)

        # Account Menu
        account_menu = menubar.addMenu("Account")
        request_deletion = account_menu.addAction("Request Account Deletion")
        request_deletion.triggered.connect(self.request_deletion)
        logout_action = account_menu.addAction("Logout")
        logout_action.triggered.connect(self.logout)
        
        self.setup_main_area()

    def view_pending_registrations(self):
        # Create container widget
        container = QWidget()
        layout = QVBoxLayout(container)
        
        # Create table
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "Name", "Username", "Role", "Registration Date", "Status", "Actions"
        ])

        def load_registrations():
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        SELECT p.first_name, p.middle_name, p.last_name,
                            a.username, a.role, cr.requested_at, a.status, 
                            cr.request_id, a.user_id
                        FROM confirmation_requests cr
                        JOIN accounts a ON cr.user_id = a.user_id
                        JOIN profiles p ON a.user_id = p.user_id
                        WHERE cr.request_type = 'Registration'
                        AND cr.status = 'Pending'
                        ORDER BY cr.requested_at DESC
                    """
                    cursor.execute(query)
                    registrations = cursor.fetchall()

                    table.setRowCount(len(registrations))
                    for i, reg in enumerate(registrations):
                        full_name = f"{reg[0]} {reg[1]} {reg[2]}"
                        table.setItem(i, 0, QTableWidgetItem(full_name))
                        table.setItem(i, 1, QTableWidgetItem(reg[3]))
                        table.setItem(i, 2, QTableWidgetItem(reg[4]))
                        table.setItem(i, 3, QTableWidgetItem(str(reg[5])))
                        table.setItem(i, 4, QTableWidgetItem(reg[6]))

                        # Action buttons
                        actions_widget = QWidget()
                        actions_layout = QHBoxLayout()
                        approve_btn = QPushButton("Approve")
                        reject_btn = QPushButton("Reject")

                        approve_btn.clicked.connect(
                            lambda checked, rid=reg[7], uid=reg[8]: 
                            self.approve_registration(rid, uid))
                        reject_btn.clicked.connect(
                            lambda checked, rid=reg[7], uid=reg[8]: 
                            self.reject_registration(rid, uid))

                        actions_layout.addWidget(approve_btn)
                        actions_layout.addWidget(reject_btn)
                        actions_widget.setLayout(actions_layout)
                        table.setCellWidget(i, 5, actions_widget)

                finally:
                    cursor.close()
                    connection.close()

        # Initial load
        load_registrations()
        
        # Add table to layout
        layout.addWidget(table)
        
        # Show in main area
        self.show_table_in_main(container, "Pending Registrations")

    def approve_registration(self, request_id, user_id):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()
                
                # First check if request exists and is pending
                cursor.execute("""
                    SELECT status FROM confirmation_requests 
                    WHERE request_id = %s AND request_type = 'Registration'
                """, (request_id,))
                result = cursor.fetchone()
                
                if not result or result[0] != 'Pending':
                    QMessageBox.warning(self, "Error", "Request no longer valid")
                    return
                
                # Update request status
                cursor.execute("""
                    UPDATE confirmation_requests 
                    SET status = 'Approved'
                    WHERE request_id = %s
                """, (request_id,))
                
                # Add record to confirmation_approvals
                cursor.execute("""
                    INSERT INTO confirmation_approvals 
                    (request_id, approved_by)
                    VALUES (%s, %s)
                """, (request_id, self.user_id))
                
                # Activate user account
                cursor.execute("""
                    UPDATE accounts 
                    SET status = 'Active'
                    WHERE user_id = %s
                """, (user_id,))
                
                connection.commit()
                QMessageBox.information(self, "Success", "Registration approved")
                self.view_pending_registrations()  # Refresh the view
                
            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
            finally:
                cursor.close()
                connection.close()

    def reject_registration(self, request_id, user_id):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()
                
                # First check if request exists and is pending
                cursor.execute("""
                    SELECT status FROM confirmation_requests 
                    WHERE request_id = %s AND request_type = 'Registration'
                    AND status = 'Pending'
                """, (request_id,))
                result = cursor.fetchone()
                
                if not result:
                    QMessageBox.warning(self, "Error", "Request no longer valid")
                    return
                
                # Update confirmation request status
                cursor.execute("""
                    UPDATE confirmation_requests 
                    SET status = 'Rejected'
                    WHERE request_id = %s
                """, (request_id,))
                
                # Add record to confirmation_approvals
                cursor.execute("""
                    INSERT INTO confirmation_approvals 
                    (request_id, approved_by) 
                    VALUES (%s, %s)
                """, (request_id, self.user_id))
                
                # Update account status
                cursor.execute("""
                    UPDATE accounts 
                    SET status = 'Inactive'
                    WHERE user_id = %s
                """, (user_id,))
                
                connection.commit()
                QMessageBox.information(self, "Success", "Registration rejected")
                self.view_pending_registrations()  # Refresh the view
                
            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
            finally:
                cursor.close()
                connection.close()

    def view_deletion_requests(self):
        # Create container widget
        container = QWidget()
        layout = QVBoxLayout(container)
        
        # Create table
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels([
            "Name", "Username", "Role", "Request Date", "Actions"
        ])

        def load_requests():
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        SELECT p.first_name, p.middle_name, p.last_name,
                            a.username, a.role, cr.requested_at, a.status, 
                            cr.request_id, a.user_id
                        FROM confirmation_requests cr
                        JOIN accounts a ON cr.user_id = a.user_id
                        JOIN profiles p ON a.user_id = p.user_id
                        WHERE cr.request_type = 'Deletion'
                        AND cr.status = 'Pending'
                        ORDER BY cr.requested_at DESC
                    """
                    cursor.execute(query)
                    requests = cursor.fetchall()

                    table.setRowCount(len(requests))
                    for i, req in enumerate(requests):
                        full_name = f"{req[0]} {req[1]} {req[2]}"
                        table.setItem(i, 0, QTableWidgetItem(full_name))
                        table.setItem(i, 1, QTableWidgetItem(req[3]))
                        table.setItem(i, 2, QTableWidgetItem(req[4]))
                        table.setItem(i, 3, QTableWidgetItem(str(req[5])))

                        # Action buttons
                        actions_widget = QWidget()
                        actions_layout = QHBoxLayout()
                        approve_btn = QPushButton("Approve")
                        reject_btn = QPushButton("Reject")

                        approve_btn.clicked.connect(
                            lambda checked, rid=req[6], uid=req[7]: 
                            self.approve_deletion(rid, uid))
                        reject_btn.clicked.connect(
                            lambda checked, rid=req[6]: 
                            self.reject_deletion(rid))

                        actions_layout.addWidget(approve_btn)
                        actions_layout.addWidget(reject_btn)
                        actions_widget.setLayout(actions_layout)
                        table.setCellWidget(i, 4, actions_widget)

                finally:
                    cursor.close()
                    connection.close()

        # Initial load
        load_requests()
        
        # Add table to layout
        layout.addWidget(table)
        
        # Show in main area
        self.show_table_in_main(container, "Deletion Requests")

    def approve_deletion(self, request_id, user_id):
        reply = QMessageBox.question(self, 'Confirm Approval',
            'Are you sure you want to approve this deletion request?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    connection.start_transaction()
                    
                    # First check if request exists and is pending
                    cursor.execute("""
                        SELECT status FROM confirmation_requests 
                        WHERE request_id = %s AND request_type = 'Deletion'
                    """, (request_id,))
                    result = cursor.fetchone()
                    
                    if not result or result[0] != 'Pending':
                        QMessageBox.warning(self, "Error", "Request no longer valid")
                        return
                    
                    # Delete any related confirmation requests if they exist
                    cursor.execute("""DELETE FROM confirmation_requests 
                        WHERE user_id = %s""", (user_id,))
                    
                    # Delete profile and account
                    cursor.execute("DELETE FROM profiles WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM accounts WHERE user_id = %s", (user_id,))
                    
                    connection.commit()
                    QMessageBox.information(self, "Success", "Deletion request approved")
                    self.view_deletion_requests()  # Refresh the view
                    
                except mysql.connector.Error as e:
                    connection.rollback()
                    QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
                finally:
                    cursor.close()
                    connection.close()

    def reject_deletion(self, request_id):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                connection.start_transaction()
                
                # Update confirmation_requests status
                cursor.execute("""
                    UPDATE confirmation_requests 
                    SET status = 'Rejected'
                    WHERE request_id = %s
                """, (request_id,))
                
                # Add record to confirmation_approvals with correct column name
                cursor.execute("""
                    INSERT INTO confirmation_approvals 
                    (request_id, approved_by) 
                    VALUES (%s, %s)
                """, (request_id, self.user_id))
                
                connection.commit()
                QMessageBox.information(self, "Success", "Deletion request rejected")
                self.view_deletion_requests()  # Refresh the view
                
            except mysql.connector.Error as e:
                connection.rollback()
                QMessageBox.critical(self, "Error", f"Error processing request: {str(e)}")
            finally:
                cursor.close()
                connection.close()  

    def manage_users(self):
        # Create container widget
        container = QWidget()
        layout = QVBoxLayout(container)

        # Add search bar layout
        search_layout = QHBoxLayout()
        search_input = QLineEdit()
        search_input.setPlaceholderText("Search by name or username...")
        search_btn = QPushButton("Search")
        search_layout.addWidget(search_input)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)

        # Create table
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "Name", "Username", "Department", "Position", "Status", "Actions"
        ])
        layout.addWidget(table)

        def load_users(search_term=""):
            connection = connect_to_database(self)
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        SELECT p.user_id, p.first_name, p.middle_name, p.last_name,
                            a.username, p.department, p.position, a.status
                        FROM profiles p
                        JOIN accounts a ON p.user_id = a.user_id
                        WHERE a.role != 'Admin' AND (
                            CONCAT(p.first_name, ' ', p.middle_name, ' ', p.last_name) LIKE %s
                            OR a.username LIKE %s
                        )
                        ORDER BY p.last_name
                    """
                    search_pattern = f"%{search_term}%" if search_term else "%"
                    cursor.execute(query, (search_pattern, search_pattern))
                    users = cursor.fetchall()

                    table.setRowCount(len(users))
                    for i, user in enumerate(users):
                        user_id = user[0]
                        full_name = f"{user[1]} {user[2]} {user[3]}"
                        table.setItem(i, 0, QTableWidgetItem(full_name))
                        table.setItem(i, 1, QTableWidgetItem(user[4]))
                        table.setItem(i, 2, QTableWidgetItem(user[5] if user[5] else "Not Set"))
                        table.setItem(i, 3, QTableWidgetItem(user[6] if user[6] else "Not Set"))
                        table.setItem(i, 4, QTableWidgetItem(user[7]))

                        # Edit Button
                        action_widget = QWidget()
                        action_layout = QHBoxLayout()
                        action_layout.setContentsMargins(0, 0, 0, 0)

                        edit_btn = QPushButton("Edit")
                        edit_btn.clicked.connect(lambda _, uid=user_id: self.edit_user_profile(uid))

                        action_layout.addWidget(edit_btn)
                        action_widget.setLayout(action_layout)
                        table.setCellWidget(i, 5, action_widget)

                finally:
                    cursor.close()
                    connection.close()

        # Connect search functionality
        search_btn.clicked.connect(lambda: load_users(search_input.text()))
        
        # Initial load
        load_users()

        # Show table in main area
        self.show_table_in_main(container, "Manage Users")

    def edit_user_profile(self, user_id):
        # Create container for editing profile
        container = QWidget()
        layout = QVBoxLayout(container)

        form_layout = QFormLayout()

        # Get current profile data
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                query = """
                    SELECT p.*, a.username, a.status
                    FROM profiles p
                    JOIN accounts a ON p.user_id = a.user_id
                    WHERE p.user_id = %s
                """
                cursor.execute(query, (user_id,))
                profile = cursor.fetchone()

                if profile:
                    # Display user's full name and username
                    full_name = f"{profile['first_name']} {profile['middle_name']} {profile['last_name']}"
                    form_layout.addRow("Name:", QLabel(full_name))
                    form_layout.addRow("Username:", QLabel(profile['username']))

                    # Editable fields
                    department_input = QLineEdit(profile['department'] if profile['department'] else "")
                    position_input = QLineEdit(profile['position'] if profile['position'] else "")

                    status_box = QComboBox()
                    status_box.addItems(["Active", "Inactive"])
                    status_box.setCurrentText(profile['status'])

                    # Add editable fields to layout
                    form_layout.addRow("Department:", department_input)
                    form_layout.addRow("Position:", position_input)
                    form_layout.addRow("Status:", status_box)

                    layout.addLayout(form_layout)

                    # Save button
                    save_btn = QPushButton("Save Changes")
                    save_btn.clicked.connect(lambda: self.save_profile_updates(
                        user_id,
                        {
                            'department': department_input,
                            'position': position_input
                        },
                        status_box.currentText()
                    ))
                    layout.addWidget(save_btn)

            finally:
                cursor.close()
                connection.close()

        # Show in main area
        self.show_table_in_main(container, "Edit User Profile")

    def save_profile_updates(self, user_id, fields, status):
        connection = connect_to_database(self)
        if connection:
            try:
                cursor = connection.cursor()
                # Update profiles for department and position
                profile_query = """
                    UPDATE profiles 
                    SET department = %s, position = %s
                    WHERE user_id = %s
                """
                cursor.execute(profile_query, (
                    fields['department'].text(),
                    fields['position'].text(),
                    user_id
                ))

                # Update accounts for status
                status_query = """
                    UPDATE accounts 
                    SET status = %s
                    WHERE user_id = %s
                """
                cursor.execute(status_query, (status, user_id))
                
                connection.commit()
                QMessageBox.information(self, "Success", "Profile updated successfully")
            except mysql.connector.Error as e:
                QMessageBox.critical(self, "Error", f"Error updating profile: {str(e)}")
            finally:
                cursor.close()
                connection.close()


class MemberDashboard(BaseDashboard):
    def __init__(self, username):
        super().__init__(username, "Member")
        self.setup_ui()

    def setup_ui(self):
        self.setGeometry(100, 100, 800, 600)
        self.setWindowTitle("Member Dashboard")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        welcome_label = QLabel(f"Welcome Member {self.username}")
        layout.addWidget(welcome_label)

        # Create menu bar
        menubar = self.menuBar()

        # Profile Menu
        profile_menu = menubar.addMenu("Profile")
        view_profile = profile_menu.addAction("My Profile")
        view_profile.triggered.connect(self.view_profile)
        
        edit_menu = profile_menu.addMenu("Edit")
        edit_account = edit_menu.addAction("Account Settings")
        edit_account.triggered.connect(lambda: self.edit_account(self.get_profile_id()))
        edit_information = edit_menu.addAction("Personal Information")
        edit_information.triggered.connect(lambda: self.edit_information(self.get_profile_id()))
        
        # Directory Menu
        directory_menu = menubar.addMenu("Directory")
        view_members = directory_menu.addAction("View Active Users")
        view_members.triggered.connect(self.view_active_users)

        # Account Menu
        account_menu = menubar.addMenu("Account")
        request_deletion = account_menu.addAction("Request Account Deletion")
        request_deletion.triggered.connect(self.request_deletion)
        logout_action = account_menu.addAction("Logout")
        logout_action.triggered.connect(self.logout)
        
        self.setup_main_area()


# --- Main ---
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = WelcomeWindow()
    window.show()
    sys.exit(app.exec())