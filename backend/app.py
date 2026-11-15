from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from openpyxl import Workbook
from io import BytesIO
from flask import send_file
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
import os
from pathlib import Path

load_dotenv(Path(__file__).with_name(".env"))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)


def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT", 3306)),
        cursorclass=DictCursor
    )


# ---------------- LOGIN ----------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Enter username and password."}), 400

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return jsonify({
                "success": True,
                "redirect_url": url_for("dashboard")
            })

        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    except Exception:
        app.logger.exception("Login failed")
        return jsonify({"success": False, "message": "Login failed. Please try again."}), 500

    finally:
        if connection:
            connection.close()


@app.route("/users/add", methods=["POST"])
def add_user():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin only.", 403

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "Employee")
    employee_id = request.form.get("employee_id") or None

    if not username or not password:
        return "Username and password are required.", 400

    if role not in ["Admin", "HR", "Employee"]:
        return "Invalid role.", 400

    if len(password) < 8:
        return "Password must contain at least 8 characters.", 400

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO users (employee_id, username, password_hash, role)
                VALUES (%s, %s, %s, %s)
            """, (employee_id, username, password_hash, role))

        connection.commit()
        return redirect(url_for("users"))

    except pymysql.IntegrityError:
        connection.rollback()
        return "Username already exists or employee already has an account.", 400

    finally:
        connection.close()


@app.route("/users")
def users():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin only.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            # Get all registered users
            cursor.execute("""
                SELECT
                    u.user_id,
                    u.username,
                    u.role,
                    u.created_at,
                    e.employee_code
                FROM users u
                LEFT JOIN employees e
                    ON u.employee_id = e.employee_id
                ORDER BY u.user_id DESC
            """)
            user_records = cursor.fetchall()

            # Get active employees
            cursor.execute("""
                SELECT employee_id, employee_code,
                       first_name, last_name
                FROM employees
                WHERE employment_status = 'Active'
                ORDER BY first_name
            """)
            employee_records = cursor.fetchall()

        return render_template(
            "users.html",
            users=user_records,
            employees=employee_records
        )

    finally:
        connection.close()

@app.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin only.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            if request.method == "POST":
                username = request.form.get("username", "").strip()
                role = request.form.get("role")
                employee_id = request.form.get("employee_id") or None

                if not username:
                    return "Username is required.", 400

                if role not in ["Admin", "HR", "Employee"]:
                    return "Invalid role.", 400

                try:
                    cursor.execute("""
                        UPDATE users
                        SET username = %s,
                            role = %s,
                            employee_id = %s
                        WHERE user_id = %s
                    """, (username, role, employee_id, user_id))

                    connection.commit()
                    return redirect(url_for("users"))

                except pymysql.IntegrityError:
                    connection.rollback()
                    return "Username already exists or employee already has an account.", 400

            cursor.execute(
                "SELECT user_id, username, role, employee_id FROM users WHERE user_id = %s",
                (user_id,)
            )
            user_record = cursor.fetchone()

            if not user_record:
                return "User not found.", 404

            cursor.execute("""
                SELECT employee_id, employee_code,
                       first_name, last_name
                FROM employees
                ORDER BY first_name
            """)
            employee_records = cursor.fetchall()

        return render_template(
            "edit_user.html",
            user=user_record,
            employees=employee_records
        )

    finally:
        connection.close()

@app.route("/users/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin only.", 403

    # Prevent admin from deleting their own account
    if user_id == session.get("user_id"):
        return "You cannot delete your own account.", 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, role FROM users WHERE user_id = %s",
                (user_id,)
            )
            user = cursor.fetchone()

            if not user:
                return "User not found.", 404

            # Prevent deletion of the last Admin account
            if user["role"] == "Admin":
                cursor.execute(
                    "SELECT COUNT(*) AS total FROM users WHERE role = 'Admin'"
                )
                admin_count = cursor.fetchone()["total"]

                if admin_count <= 1:
                    return "Cannot delete the last Admin account.", 400

            cursor.execute(
                "DELETE FROM users WHERE user_id = %s",
                (user_id,)
            )

        connection.commit()
        return redirect(url_for("users"))

    finally:
        connection.close()

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("home"))

    connection = get_db_connection()
    cursor = connection.cursor()

    # Total Employees
    cursor.execute("SELECT COUNT(*) AS total FROM employees")
    total_employees = cursor.fetchone()["total"]

    # Active Employees
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM employees
        WHERE employment_status = 'Active'
    """)
    active_employees = cursor.fetchone()["total"]

    # Total Departments
    cursor.execute("SELECT COUNT(*) AS total FROM departments")
    total_departments = cursor.fetchone()["total"]

    # Pending Leave Requests
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM leave_requests
        WHERE status = 'Pending'
    """)
    pending_leaves = cursor.fetchone()["total"]

    # Today's Attendance
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM attendance
        WHERE attendance_date = CURDATE()
    """)
    today_attendance = cursor.fetchone()["total"]

    # Current Month Payroll
    cursor.execute("""
        SELECT COALESCE(SUM(net_salary), 0) AS total
        FROM payroll
        WHERE pay_month = MONTH(CURDATE())
        AND pay_year = YEAR(CURDATE())
    """)
    monthly_payroll = cursor.fetchone()["total"]

    cursor.close()
    connection.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        total_employees=total_employees,
        active_employees=active_employees,
        total_departments=total_departments,
        pending_leaves=pending_leaves,
        today_attendance=today_attendance,
        monthly_payroll=monthly_payroll
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------- EMPLOYEE LIST ----------------

@app.route("/employees")
def employees():
    if "user_id" not in session:
        return redirect(url_for("home"))

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT e.*, d.department_name
                FROM employees e
                LEFT JOIN departments d
                ON e.department_id = d.department_id
                ORDER BY e.employee_id DESC
            """)
            employee_list = cursor.fetchall()

            cursor.execute("""
                SELECT department_id, department_name
                FROM departments
                ORDER BY department_name
            """)
            department_list = cursor.fetchall()

        return render_template(
            "employees.html",
            employees=employee_list,
            departments=department_list
        )

    except Exception:
        app.logger.exception("Could not load employees")
        return "Unable to load employee records. Check the server terminal.", 500

    finally:
        if connection:
            connection.close()


# ---------------- ADD EMPLOYEE ----------------

@app.route("/employees/add", methods=["POST"])
def add_employee():
    if "user_id" not in session:
        return redirect(url_for("home"))

    fields = [
        "employee_code", "first_name", "last_name", "email",
        "phone", "gender", "date_of_birth", "date_of_joining",
        "job_title", "department_id", "employment_status"
    ]

    data = {field: request.form.get(field, "").strip() for field in fields}

    if not data["employee_code"] or not data["first_name"] or not data["email"] or not data["date_of_joining"] or not data["department_id"]:
        return "Please fill all required fields.", 400

    data["last_name"] = data["last_name"] or None
    data["phone"] = data["phone"] or None
    data["gender"] = data["gender"] or None
    data["date_of_birth"] = data["date_of_birth"] or None
    data["job_title"] = data["job_title"] or None
    data["employment_status"] = data["employment_status"] or "Active"

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO employees (
                    employee_code, first_name, last_name, email,
                    phone, gender, date_of_birth, date_of_joining,
                    job_title, department_id, employment_status
                )
                VALUES (
                    %(employee_code)s, %(first_name)s, %(last_name)s,
                    %(email)s, %(phone)s, %(gender)s, %(date_of_birth)s,
                    %(date_of_joining)s, %(job_title)s, %(department_id)s,
                    %(employment_status)s
                )
            """, data)

        connection.commit()
        return redirect(url_for("employees"))

    except pymysql.err.IntegrityError:
        if connection:
            connection.rollback()
        return "Employee Code or Email already exists. Please use different details.", 400

    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Employee creation failed")
        return "Unable to add employee. Check the server terminal.", 500

    finally:
        if connection:
            connection.close()


# ---------------- EDIT EMPLOYEE ----------------

@app.route("/employees/edit/<int:employee_id>", methods=["GET", "POST"])
def edit_employee(employee_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            if request.method == "POST":
                data = request.form

                cursor.execute("""
                    UPDATE employees SET
                        employee_code=%s,
                        first_name=%s,
                        last_name=%s,
                        email=%s,
                        phone=%s,
                        gender=%s,
                        date_of_birth=%s,
                        date_of_joining=%s,
                        job_title=%s,
                        department_id=%s,
                        employment_status=%s
                    WHERE employee_id=%s
                """, (
                    data.get("employee_code"),
                    data.get("first_name"),
                    data.get("last_name") or None,
                    data.get("email"),
                    data.get("phone") or None,
                    data.get("gender") or None,
                    data.get("date_of_birth") or None,
                    data.get("date_of_joining"),
                    data.get("job_title") or None,
                    data.get("department_id"),
                    data.get("employment_status"),
                    employee_id
                ))

                connection.commit()
                return redirect(url_for("employees"))

            cursor.execute(
                "SELECT * FROM employees WHERE employee_id=%s",
                (employee_id,)
            )
            employee = cursor.fetchone()

            cursor.execute("SELECT * FROM departments ORDER BY department_name")
            department_list = cursor.fetchall()

        if not employee:
            return "Employee not found.", 404

        return render_template(
            "edit_employee.html",
            employee=employee,
            departments=department_list
        )

    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Employee update failed")
        return "Unable to edit employee. Check the server terminal.", 500

    finally:
        if connection:
            connection.close()


# ---------------- DELETE EMPLOYEE ----------------

@app.route("/employees/delete/<int:employee_id>", methods=["POST"])
def delete_employee(employee_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM employees WHERE employee_id=%s",
                (employee_id,)
            )

        connection.commit()
        return redirect(url_for("employees"))

    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Employee deletion failed")
        return "Unable to delete employee. Check the server terminal.", 500

    finally:
        if connection:
            connection.close()
            
@app.route("/departments")
def departments():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM departments ORDER BY department_id")
    department_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "departments.html",
        departments=department_list
    )
@app.route("/departments/add", methods=["POST"])
def add_department():
    if "user_id" not in session:
        return redirect(url_for("login"))

    department_name = request.form.get("department_name", "").strip()
    description = request.form.get("description", "").strip()

    if not department_name:
        return "Department name is required", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO departments (department_name, description)
            VALUES (%s, %s)
            """,
            (department_name, description)
        )
        connection.commit()

    except pymysql.IntegrityError:
        connection.rollback()
        cursor.close()
        connection.close()
        return "Department already exists!", 400

    cursor.close()
    connection.close()

    return redirect(url_for("departments"))

@app.route("/departments/edit/<int:department_id>", methods=["GET", "POST"])
def edit_department(department_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":
        department_name = request.form.get("department_name", "").strip()
        description = request.form.get("description", "").strip()

        if not department_name:
            return "Department name is required", 400

        try:
            cursor.execute(
                """
                UPDATE departments
                SET department_name = %s, description = %s
                WHERE department_id = %s
                """,
                (department_name, description, department_id)
            )
            connection.commit()

        except pymysql.IntegrityError:
            connection.rollback()
            cursor.close()
            connection.close()
            return "Department name already exists!", 400

        cursor.close()
        connection.close()
        return redirect(url_for("departments"))

    cursor.execute(
        "SELECT * FROM departments WHERE department_id = %s",
        (department_id,)
    )
    department = cursor.fetchone()

    cursor.close()
    connection.close()

    if not department:
        return "Department not found", 404

    return render_template("edit_department.html", department=department)

@app.route("/departments/delete/<int:department_id>", methods=["POST"])
def delete_department(department_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            "DELETE FROM departments WHERE department_id = %s",
            (department_id,)
        )
        connection.commit()

    except pymysql.IntegrityError:
        connection.rollback()
        cursor.close()
        connection.close()
        return "Cannot delete this department because employees are assigned to it.", 400

    cursor.close()
    connection.close()

    return redirect(url_for("departments"))


@app.route("/leave-requests")
def leave_requests():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    employee_id = request.args.get("employee_id", "")
    leave_type = request.args.get("leave_type", "")
    status = request.args.get("status", "")

    query = """
        SELECT
            l.*,
            e.employee_code,
            e.first_name,
            e.last_name
        FROM leave_requests l
        JOIN employees e ON l.employee_id = e.employee_id
        WHERE 1=1
    """

    values = []

    if employee_id:
        query += " AND l.employee_id = %s"
        values.append(employee_id)

    if leave_type in ["Casual", "Sick", "Earned", "Other"]:
        query += " AND l.leave_type = %s"
        values.append(leave_type)

    if status in ["Pending", "Approved", "Rejected"]:
        query += " AND l.status = %s"
        values.append(status)

    query += " ORDER BY l.applied_at DESC"

    cursor.execute(query, values)
    leave_list = cursor.fetchall()

    cursor.execute("""
        SELECT employee_id, employee_code, first_name, last_name
        FROM employees
        WHERE employment_status = 'Active'
        ORDER BY first_name
    """)

    employees = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "leave_requests.html",
        leaves=leave_list,
        employees=employees,
        selected_employee=employee_id,
        selected_leave_type=leave_type,
        selected_status=status
    )


@app.route("/payroll")
def payroll():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    employee_id = request.args.get("employee_id", "")
    pay_month = request.args.get("pay_month", "")
    pay_year = request.args.get("pay_year", "")
    payment_status = request.args.get("payment_status", "")

    query = """
        SELECT
            p.*,
            e.employee_code,
            e.first_name,
            e.last_name
        FROM payroll p
        JOIN employees e ON p.employee_id = e.employee_id
        WHERE 1=1
    """

    values = []

    if employee_id:
        query += " AND p.employee_id = %s"
        values.append(employee_id)

    if pay_month.isdigit() and 1 <= int(pay_month) <= 12:
        query += " AND p.pay_month = %s"
        values.append(int(pay_month))

    if pay_year.isdigit() and 2000 <= int(pay_year) <= 2100:
        query += " AND p.pay_year = %s"
        values.append(int(pay_year))

    if payment_status in ["Pending", "Paid"]:
        query += " AND p.payment_status = %s"
        values.append(payment_status)

    query += " ORDER BY p.pay_year DESC, p.pay_month DESC"

    cursor.execute(query, values)
    payroll_records = cursor.fetchall()

    cursor.execute("""
        SELECT employee_id, employee_code, first_name, last_name
        FROM employees
        WHERE employment_status = 'Active'
        ORDER BY first_name
    """)

    employees = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "payroll.html",
        payroll_records=payroll_records,
        employees=employees,
        selected_employee=employee_id,
        selected_month=pay_month,
        selected_year=pay_year,
        selected_payment_status=payment_status
    )

@app.route("/payroll/add", methods=["POST"])
def add_payroll():
    if "user_id" not in session:
        return redirect(url_for("login"))

    employee_id = request.form.get("employee_id")
    pay_month = request.form.get("pay_month")
    pay_year = request.form.get("pay_year")
    basic_salary = request.form.get("basic_salary")
    allowances = request.form.get("allowances") or "0"
    deductions = request.form.get("deductions") or "0"

    try:
        pay_month = int(pay_month)
        pay_year = int(pay_year)
        basic_salary = float(basic_salary)
        allowances = float(allowances)
        deductions = float(deductions)

        if not 1 <= pay_month <= 12:
            return "Invalid pay month.", 400

        if not 2000 <= pay_year <= 2100:
            return "Invalid pay year.", 400

        if min(basic_salary, allowances, deductions) < 0:
            return "Salary values cannot be negative.", 400

        net_salary = basic_salary + allowances - deductions

        if net_salary < 0:
            return "Deductions cannot exceed total salary.", 400

    except (ValueError, TypeError):
        return "Please enter valid payroll details.", 400

    if not employee_id:
        return "Please select an employee.", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT INTO payroll
            (employee_id, pay_month, pay_year, basic_salary,
             allowances, deductions, net_salary, payment_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'Pending')
        """, (
            employee_id, pay_month, pay_year, basic_salary,
            allowances, deductions, net_salary
        ))

        connection.commit()

    except pymysql.IntegrityError:
        connection.rollback()
        cursor.close()
        connection.close()
        return "Invalid employee or duplicate payroll record.", 400

    cursor.close()
    connection.close()

    return redirect(url_for("payroll"))


@app.route("/payroll/update-status/<int:payroll_id>", methods=["POST"])
def update_payroll_status(payroll_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    payment_status = request.form.get("payment_status")

    if payment_status not in ["Pending", "Paid"]:
        return "Invalid payment status.", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    if payment_status == "Paid":
        cursor.execute("""
            UPDATE payroll
            SET payment_status = 'Paid',
                payment_date = CURDATE()
            WHERE payroll_id = %s
        """, (payroll_id,))
    else:
        cursor.execute("""
            UPDATE payroll
            SET payment_status = 'Pending',
                payment_date = NULL
            WHERE payroll_id = %s
        """, (payroll_id,))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("payroll"))


@app.route("/payroll/edit/<int:payroll_id>", methods=["GET", "POST"])
def edit_payroll(payroll_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":
        employee_id = request.form.get("employee_id")
        pay_month = request.form.get("pay_month")
        pay_year = request.form.get("pay_year")
        basic_salary = request.form.get("basic_salary")
        allowances = request.form.get("allowances") or "0"
        deductions = request.form.get("deductions") or "0"

        try:
            pay_month = int(pay_month)
            pay_year = int(pay_year)
            basic_salary = float(basic_salary)
            allowances = float(allowances)
            deductions = float(deductions)

            if not 1 <= pay_month <= 12:
                raise ValueError

            if not 2000 <= pay_year <= 2100:
                raise ValueError

            if min(basic_salary, allowances, deductions) < 0:
                raise ValueError

            net_salary = basic_salary + allowances - deductions

            if net_salary < 0:
                raise ValueError

            if not employee_id:
                raise ValueError

        except (ValueError, TypeError):
            cursor.close()
            connection.close()
            return "Invalid payroll details.", 400

        try:
            cursor.execute("""
                UPDATE payroll
                SET employee_id = %s,
                    pay_month = %s,
                    pay_year = %s,
                    basic_salary = %s,
                    allowances = %s,
                    deductions = %s,
                    net_salary = %s
                WHERE payroll_id = %s
            """, (
                employee_id, pay_month, pay_year,
                basic_salary, allowances, deductions,
                net_salary, payroll_id
            ))

            connection.commit()

        except pymysql.IntegrityError:
            connection.rollback()
            cursor.close()
            connection.close()
            return "Invalid employee or duplicate payroll record.", 400

        cursor.close()
        connection.close()
        return redirect(url_for("payroll"))

    cursor.execute(
        "SELECT * FROM payroll WHERE payroll_id = %s",
        (payroll_id,)
    )
    record = cursor.fetchone()

    if not record:
        cursor.close()
        connection.close()
        return "Payroll record not found.", 404

    cursor.execute("""
        SELECT employee_id, employee_code, first_name, last_name
        FROM employees
        WHERE employment_status = 'Active'
        ORDER BY first_name
    """)
    employees = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "edit_payroll.html",
        record=record,
        employees=employees
    )


@app.route("/payroll/delete/<int:payroll_id>", methods=["POST"])
def delete_payroll(payroll_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM payroll WHERE payroll_id = %s",
        (payroll_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("payroll"))

@app.route("/attendance")
def attendance():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    attendance_date = request.args.get("attendance_date", "")
    employee_id = request.args.get("employee_id", "")

    query = """
        SELECT
            a.*,
            e.employee_code,
            e.first_name,
            e.last_name
        FROM attendance a
        JOIN employees e ON a.employee_id = e.employee_id
        WHERE 1=1
    """

    values = []

    if attendance_date:
        query += " AND a.attendance_date = %s"
        values.append(attendance_date)

    if employee_id:
        query += " AND a.employee_id = %s"
        values.append(employee_id)

    query += " ORDER BY a.attendance_date DESC"

    cursor.execute(query, values)
    attendance_records = cursor.fetchall()

    cursor.execute("""
        SELECT employee_id, employee_code, first_name, last_name
        FROM employees
        WHERE employment_status = 'Active'
        ORDER BY first_name
    """)

    employees = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "attendance.html",
        attendance_records=attendance_records,
        employees=employees,
        selected_date=attendance_date,
        selected_employee=employee_id
    )

@app.route("/attendance/add", methods=["POST"])
def add_attendance():
    if "user_id" not in session:
        return redirect(url_for("login"))

    employee_id = request.form.get("employee_id")
    attendance_date = request.form.get("attendance_date")
    check_in = request.form.get("check_in") or None
    check_out = request.form.get("check_out") or None
    status = request.form.get("status")

    allowed_statuses = ["Present", "Absent", "Late", "Half Day"]

    if not employee_id or not attendance_date:
        return "Employee and attendance date are required.", 400

    if status not in allowed_statuses:
        return "Invalid attendance status.", 400

    if check_in and check_out and check_out <= check_in:
        return "Check-out time must be later than check-in time.", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO attendance
            (employee_id, attendance_date, check_in, check_out, status)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (employee_id, attendance_date, check_in, check_out, status)
        )

        connection.commit()

    except pymysql.IntegrityError:
        connection.rollback()
        cursor.close()
        connection.close()
        return "Invalid employee selection or attendance record.", 400

    cursor.close()
    connection.close()

    return redirect(url_for("attendance"))


@app.route("/leave/add", methods=["POST"])
def add_leave():
    if "user_id" not in session:
        return redirect(url_for("login"))

    employee_id = request.form.get("employee_id")
    leave_type = request.form.get("leave_type")
    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")
    reason = request.form.get("reason")

    allowed_types = ["Casual", "Sick", "Earned", "Other"]

    if not employee_id or not leave_type or not start_date or not end_date:
        return "All required fields must be filled.", 400

    if leave_type not in allowed_types:
        return "Invalid leave type.", 400

    if end_date < start_date:
        return "End date cannot be before start date.", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT INTO leave_requests
            (employee_id, leave_type, start_date, end_date, reason, status)
            VALUES (%s, %s, %s, %s, %s, 'Pending')
        """, (employee_id, leave_type, start_date, end_date, reason))

        connection.commit()

    except pymysql.IntegrityError:
        connection.rollback()
        cursor.close()
        connection.close()
        return "Invalid employee selection.", 400

    cursor.close()
    connection.close()

    return redirect(url_for("leave_requests"))


@app.route("/leave/update-status/<int:leave_id>", methods=["POST"])
def update_leave_status(leave_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    status = request.form.get("status")

    allowed_statuses = ["Approved", "Rejected"]

    if status not in allowed_statuses:
        return "Invalid leave status.", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE leave_requests
        SET status = %s
        WHERE leave_id = %s
    """, (status, leave_id))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("leave_requests"))

@app.route("/attendance/edit/<int:attendance_id>", methods=["GET", "POST"])
def edit_attendance(attendance_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":
        employee_id = request.form.get("employee_id")
        attendance_date = request.form.get("attendance_date")
        check_in = request.form.get("check_in") or None
        check_out = request.form.get("check_out") or None
        status = request.form.get("status")

        allowed_statuses = ["Present", "Absent", "Late", "Half Day"]

        if not employee_id or not attendance_date:
            cursor.close()
            connection.close()
            return "Employee and date are required.", 400

        if status not in allowed_statuses:
            cursor.close()
            connection.close()
            return "Invalid attendance status.", 400

        if check_in and check_out and check_out <= check_in:
            cursor.close()
            connection.close()
            return "Check-out must be later than check-in.", 400

        try:
            cursor.execute("""
                UPDATE attendance
                SET employee_id = %s,
                    attendance_date = %s,
                    check_in = %s,
                    check_out = %s,
                    status = %s
                WHERE attendance_id = %s
            """, (
                employee_id, attendance_date,
                check_in, check_out, status, attendance_id
            ))

            connection.commit()

        except pymysql.IntegrityError:
            connection.rollback()
            cursor.close()
            connection.close()
            return "Attendance already exists for this employee on this date.", 400

        cursor.close()
        connection.close()
        return redirect(url_for("attendance"))

    cursor.execute("""
        SELECT * FROM attendance
        WHERE attendance_id = %s
    """, (attendance_id,))

    record = cursor.fetchone()

    cursor.execute("""
        SELECT employee_id, employee_code, first_name, last_name
        FROM employees
        WHERE employment_status = 'Active'
        ORDER BY first_name
    """)

    employees = cursor.fetchall()

    cursor.close()
    connection.close()

    if not record:
        return "Attendance record not found.", 404

    return render_template(
        "edit_attendance.html",
        record=record,
        employees=employees
    )

@app.route("/attendance/delete/<int:attendance_id>", methods=["POST"])
def delete_attendance(attendance_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM attendance WHERE attendance_id = %s",
        (attendance_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("attendance"))

# ---------------- DATABASE TEST ----------------

@app.route("/db-test")
def database_test():
    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()

        return jsonify({
            "message": "MySQL Connected Successfully!",
            "tables": tables
        })

    except Exception:
        app.logger.exception("Database test failed")
        return jsonify({"message": "Database connection failed"}), 500

    finally:
        if connection:
            connection.close()

@app.route("/reports/employees")
def employee_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    e.email,
                    e.phone,
                    e.job_title,
                    d.department_name,
                    e.employment_status,
                    e.date_of_joining
                FROM employees e
                LEFT JOIN departments d
                    ON e.department_id = d.department_id
                ORDER BY e.employee_id DESC
            """)
            employees = cursor.fetchall()

        return render_template(
            "employee_report.html",
            employees=employees
        )

    finally:
        connection.close()


# ---------------- ATTENDANCE REPORT ----------------

@app.route("/reports/attendance")
def attendance_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    a.attendance_date,
                    a.check_in,
                    a.check_out,
                    a.status
                FROM attendance a
                JOIN employees e
                    ON a.employee_id = e.employee_id
                ORDER BY a.attendance_date DESC
            """)

            attendance_records = cursor.fetchall()

        return render_template(
            "attendance_report.html",
            attendance_records=attendance_records,
            total_records=len(attendance_records)
        )

    finally:
        connection.close()

# ---------------- LEAVE REPORT ----------------

@app.route("/reports/leaves")
def leave_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    l.leave_type,
                    l.start_date,
                    l.end_date,
                    l.reason,
                    l.status,
                    l.applied_at
                FROM leave_requests l
                JOIN employees e
                    ON l.employee_id = e.employee_id
                ORDER BY l.applied_at DESC
            """)

            leave_records = cursor.fetchall()

        return render_template(
            "leave_report.html",
            leave_records=leave_records,
            total_records=len(leave_records)
        )

    finally:
        connection.close()

# ---------------- PAYROLL REPORT ----------------

@app.route("/reports/payroll")
def payroll_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    p.pay_month,
                    p.pay_year,
                    p.basic_salary,
                    p.allowances,
                    p.deductions,
                    p.net_salary,
                    p.payment_status,
                    p.payment_date
                FROM payroll p
                JOIN employees e
                    ON p.employee_id = e.employee_id
                ORDER BY p.pay_year DESC, p.pay_month DESC
            """)

            payroll_records = cursor.fetchall()

        return render_template(
            "payroll_report.html",
            payroll_records=payroll_records,
            total_records=len(payroll_records)
        )

    finally:
        connection.close()

# ---------------- EXPORT EMPLOYEE REPORT TO EXCEL ----------------

@app.route("/reports/employees/export")
def export_employee_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    e.email,
                    e.phone,
                    e.job_title,
                    d.department_name,
                    e.employment_status,
                    e.date_of_joining
                FROM employees e
                LEFT JOIN departments d
                    ON e.department_id = d.department_id
                ORDER BY e.employee_id DESC
            """)

            employees = cursor.fetchall()

    finally:
        connection.close()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Employee Report"

    headers = [
        "Employee Code",
        "First Name",
        "Last Name",
        "Email",
        "Phone",
        "Job Title",
        "Department",
        "Status",
        "Date of Joining"
    ]

    sheet.append(headers)

    for employee in employees:
        sheet.append([
            employee["employee_code"],
            employee["first_name"],
            employee["last_name"],
            employee["email"],
            employee["phone"],
            employee["job_title"],
            employee["department_name"],
            employee["employment_status"],
            employee["date_of_joining"]
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="employee_report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ---------------- EXPORT EMPLOYEE REPORT TO PDF ----------------

@app.route("/reports/employees/pdf")
def export_employee_pdf():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    e.email,
                    e.phone,
                    e.job_title,
                    d.department_name,
                    e.employment_status,
                    e.date_of_joining
                FROM employees e
                LEFT JOIN departments d
                    ON e.department_id = d.department_id
                ORDER BY e.employee_id DESC
            """)

            employees = cursor.fetchall()

    finally:
        connection.close()

    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=landscape(A4)
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Employee Report", styles["Title"]))
    elements.append(Spacer(1, 15))

    data = [[
        "Code", "First Name", "Last Name", "Email",
        "Phone", "Job Title", "Department", "Status", "Joining Date"
    ]]

    for employee in employees:
        data.append([
            str(employee["employee_code"] or ""),
            str(employee["first_name"] or ""),
            str(employee["last_name"] or ""),
            str(employee["email"] or ""),
            str(employee["phone"] or ""),
            str(employee["job_title"] or ""),
            str(employee["department_name"] or ""),
            str(employee["employment_status"] or ""),
            str(employee["date_of_joining"] or "")
        ])

    table = Table(data, repeatRows=1)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243B55")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(table)

    document.build(elements)

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="employee_report.pdf",
        mimetype="application/pdf"
    )
# ---------------- EXPORT ATTENDANCE REPORT TO EXCEL ----------------

@app.route("/reports/attendance/export")
def export_attendance_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    a.attendance_date,
                    a.check_in,
                    a.check_out,
                    a.status
                FROM attendance a
                JOIN employees e
                    ON a.employee_id = e.employee_id
                ORDER BY a.attendance_date DESC
            """)

            records = cursor.fetchall()

    finally:
        connection.close()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Attendance Report"

    sheet.append([
        "Employee Code",
        "First Name",
        "Last Name",
        "Date",
        "Check In",
        "Check Out",
        "Status"
    ])

    for record in records:
        sheet.append([
            record["employee_code"],
            record["first_name"],
            record["last_name"],
            record["attendance_date"],
            record["check_in"],
            record["check_out"],
            record["status"]
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="attendance_report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ---------------- EXPORT ATTENDANCE REPORT TO PDF ----------------

@app.route("/reports/attendance/pdf")
def export_attendance_pdf():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    a.attendance_date,
                    a.check_in,
                    a.check_out,
                    a.status
                FROM attendance a
                JOIN employees e
                    ON a.employee_id = e.employee_id
                ORDER BY a.attendance_date DESC
            """)

            records = cursor.fetchall()

    finally:
        connection.close()

    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=landscape(A4)
    )

    styles = getSampleStyleSheet()
    elements = [
        Paragraph("Attendance Report", styles["Title"]),
        Spacer(1, 15)
    ]

    data = [[
        "Employee Code", "First Name", "Last Name",
        "Date", "Check In", "Check Out", "Status"
    ]]

    for record in records:
        data.append([
            str(record["employee_code"] or ""),
            str(record["first_name"] or ""),
            str(record["last_name"] or ""),
            str(record["attendance_date"] or ""),
            str(record["check_in"] or "-"),
            str(record["check_out"] or "-"),
            str(record["status"] or "")
        ])

    table = Table(data, repeatRows=1)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243B55")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(table)
    document.build(elements)

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="attendance_report.pdf",
        mimetype="application/pdf"
    )

# ---------------- EXPORT LEAVE REPORT TO EXCEL ----------------

@app.route("/reports/leaves/export")
def export_leave_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    l.leave_type,
                    l.start_date,
                    l.end_date,
                    l.reason,
                    l.status,
                    l.applied_at
                FROM leave_requests l
                JOIN employees e
                    ON l.employee_id = e.employee_id
                ORDER BY l.applied_at DESC
            """)

            records = cursor.fetchall()

    finally:
        connection.close()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Leave Report"

    sheet.append([
        "Employee Code",
        "First Name",
        "Last Name",
        "Leave Type",
        "Start Date",
        "End Date",
        "Reason",
        "Status",
        "Applied At"
    ])

    for record in records:
        sheet.append([
            record["employee_code"],
            record["first_name"],
            record["last_name"],
            record["leave_type"],
            record["start_date"],
            record["end_date"],
            record["reason"],
            record["status"],
            record["applied_at"]
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="leave_report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ---------------- EXPORT LEAVE REPORT TO PDF ----------------

@app.route("/reports/leaves/pdf")
def export_leave_pdf():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    l.leave_type,
                    l.start_date,
                    l.end_date,
                    l.reason,
                    l.status
                FROM leave_requests l
                JOIN employees e
                    ON l.employee_id = e.employee_id
                ORDER BY l.applied_at DESC
            """)

            records = cursor.fetchall()

    finally:
        connection.close()

    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=landscape(A4)
    )

    styles = getSampleStyleSheet()
    elements = [
        Paragraph("Leave Report", styles["Title"]),
        Spacer(1, 15)
    ]

    data = [[
        "Employee Code", "First Name", "Last Name",
        "Leave Type", "Start Date", "End Date",
        "Reason", "Status"
    ]]

    for record in records:
        data.append([
            str(record["employee_code"] or ""),
            str(record["first_name"] or ""),
            str(record["last_name"] or ""),
            str(record["leave_type"] or ""),
            str(record["start_date"] or ""),
            str(record["end_date"] or ""),
            str(record["reason"] or "-"),
            str(record["status"] or "")
        ])

    table = Table(data, repeatRows=1)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243B55")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(table)
    document.build(elements)

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="leave_report.pdf",
        mimetype="application/pdf"
    )

# ---------------- EXPORT PAYROLL REPORT TO EXCEL ----------------

@app.route("/reports/payroll/export")
def export_payroll_report():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    p.pay_month,
                    p.pay_year,
                    p.basic_salary,
                    p.allowances,
                    p.deductions,
                    p.net_salary,
                    p.payment_status,
                    p.payment_date
                FROM payroll p
                JOIN employees e
                    ON p.employee_id = e.employee_id
                ORDER BY p.pay_year DESC, p.pay_month DESC
            """)

            records = cursor.fetchall()

    finally:
        connection.close()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Payroll Report"

    sheet.append([
        "Employee Code",
        "First Name",
        "Last Name",
        "Month",
        "Year",
        "Basic Salary",
        "Allowances",
        "Deductions",
        "Net Salary",
        "Payment Status",
        "Payment Date"
    ])

    for record in records:
        sheet.append([
            record["employee_code"],
            record["first_name"],
            record["last_name"],
            record["pay_month"],
            record["pay_year"],
            record["basic_salary"],
            record["allowances"],
            record["deductions"],
            record["net_salary"],
            record["payment_status"],
            record["payment_date"]
        ])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="payroll_report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ---------------- EXPORT PAYROLL REPORT TO PDF ----------------

@app.route("/reports/payroll/pdf")
def export_payroll_pdf():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["Admin", "HR"]:
        return "Access denied.", 403

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    e.employee_code,
                    e.first_name,
                    e.last_name,
                    p.pay_month,
                    p.pay_year,
                    p.basic_salary,
                    p.allowances,
                    p.deductions,
                    p.net_salary,
                    p.payment_status,
                    p.payment_date
                FROM payroll p
                JOIN employees e
                    ON p.employee_id = e.employee_id
                ORDER BY p.pay_year DESC, p.pay_month DESC
            """)

            records = cursor.fetchall()

    finally:
        connection.close()

    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=landscape(A4)
    )

    styles = getSampleStyleSheet()
    elements = [
        Paragraph("Payroll Report", styles["Title"]),
        Spacer(1, 15)
    ]

    data = [[
        "Code", "First Name", "Last Name", "Month",
        "Year", "Basic Salary", "Allowances",
        "Deductions", "Net Salary", "Status", "Payment Date"
    ]]

    for record in records:
        data.append([
            str(record["employee_code"] or ""),
            str(record["first_name"] or ""),
            str(record["last_name"] or ""),
            str(record["pay_month"] or ""),
            str(record["pay_year"] or ""),
            str(record["basic_salary"] or ""),
            str(record["allowances"] or ""),
            str(record["deductions"] or ""),
            str(record["net_salary"] or ""),
            str(record["payment_status"] or ""),
            str(record["payment_date"] or "-")
        ])

    table = Table(data, repeatRows=1)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243B55")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(table)
    document.build(elements)

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="payroll_report.pdf",
        mimetype="application/pdf"
    )
    
if __name__ == "__main__":
    app.run(debug=True)