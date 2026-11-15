# Employee Management System (EMS)

## Project Overview
The Employee Management System is a web-based application developed to simplify and manage daily employee-related activities in an organization. It provides a centralized platform for managing employee information, attendance, leave requests, payroll, and user accounts.

## Technologies Used
- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask
- **Database:** MySQL
- **Database Connectivity:** PyMySQL
- **Password Security:** Flask-Bcrypt
- **Excel Reports:** OpenPyXL
- **PDF Reports:** ReportLab

## Main Features

### 1. Admin Login
- Secure login system
- Role-based user management

### 2. Employee Management
- Add, view, edit, and delete employee details
- Search employee records

### 3. Department Management
- Create and manage departments
- Edit and delete department details

### 4. Attendance Management
- Record employee attendance
- Edit and delete attendance records
- Filter attendance by date and employee
- Prevent duplicate daily attendance records

### 5. Leave Management
- Apply for employee leave
- Approve or reject leave requests
- Filter leave records

### 6. Payroll Management
- Add and update payroll details
- Calculate net salary
- Mark payments as Paid or Pending
- Filter payroll records

### 7. Reports
- Employee reports
- Attendance reports
- Leave reports
- Payroll reports
- Export reports in Excel and PDF formats

## Installation and Setup

1. Clone or download this repository.
2. Open the project folder in VS Code.
3. Create and activate a Python virtual environment.
4. Install the required Python packages.
5. Configure the MySQL database and environment variables.
6. Run the application:

```bash
python backend/app.py
```

7. Open the application in your browser:

```text
http://127.0.0.1:5000
```

## Project Purpose
This project was developed as a practical learning project to understand full-stack web application development, database integration, authentication, CRUD operations, and report generation.
