# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teacher-only activity management with role-based authentication
- Persistent SQLite storage

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Configure the first teacher account (the password is hashed before storage):

   ```
   export TEACHER_USERNAME=teacher
   export TEACHER_PASSWORD='use-a-password-with-at-least-8-characters'
   ```

3. Run the application:

   ```
   python app.py
   ```

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |
| POST   | `/auth/login`                                                    | Log in and receive a bearer token                                    |
| POST   | `/auth/register`                                                 | Create a student account                                             |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

Activities, users, sessions, and participants are stored in `activities.db` by default.
Set `DATABASE_PATH` to use a different database location. Only teachers and administrators
can add or remove participants; students can view the activity list.
