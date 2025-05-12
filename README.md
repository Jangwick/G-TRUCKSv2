# G-TRUCKS - Waste Collector Distribution Management System

G-TRUCKS is a comprehensive management system for waste collection operations, connecting administrators, collectors, and residents with real-time tracking and scheduling capabilities.

## Features

### Admin
- Barangay Registration (Quezon City, districts 1 to 6)
- Waste Collection Scheduling
- User Management
- Collector Registration and Management
- Live Tracking of Collection Vehicles
- Reporting and Analytics

### Users
- User Profile Management
- Real-time Collection Notifications
- Live Tracking of Waste Collection Vehicles

### Collectors
- Status Updates
- Location Tracking
- Schedule Management

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy with SQLite (can be scaled to PostgreSQL)
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Authentication**: Flask-Login
- **Maps**: Leaflet.js
- **Real-time Updates**: Flask-SocketIO

## Setup Instructions

1. **Install Dependencies**:
   ```
   pip install -r requirements.txt
   ```

2. **Initialize the Database**:
   You have two options to initialize the database:
   
   **Option 1**: Run the initialization script:
   ```
   python init_db.py
   ```
   
   **Option 2**: Visit `/setup` route after starting the application.

3. **Run the Application**:
   ```
   python app.py
   ```

4. **Default Admin Credentials**:
   - Username: `admin`
   - Password: `admin123`

5. **Template Structure**:
   This application uses the following template structure:
   ```
   /templates
     /admin       - Admin interface templates
     /user        - User interface templates
     /collector   - Collector interface templates
   ```
   If you get a "TemplateNotFound" error, ensure that these directories exist and contain the necessary template files.

   Required template files include:
   - `/templates/admin/dashboard.html`
   - `/templates/admin/barangays.html`
   - `/templates/admin/collectors.html`
   - `/templates/admin/schedules.html`
   - `/templates/admin/users.html`
   - `/templates/admin/tracking.html`
   - `/templates/admin/reports.html`

   You can use the following command to verify all templates exist:
   ```
   dir /b "c:\work in progress\G-TRUCKSv2\templates\admin\"
   ```

6. **Common Issues**:
   - If you see an error like `AssertionError: View function mapping is overwriting an existing endpoint function`, 
     check for duplicate route definitions in app.py. Each route endpoint should be defined only once.
     
     Example of a duplicate route that causes errors:
     ```python
     @app.route('/collector/dashboard')
     def collector_dashboard():
         # First implementation
         
     # Later in the code
     @app.route('/collector/dashboard')  # This causes an error - duplicate route
     def collector_dashboard():
         # Second implementation
     ```
     
     To fix, ensure each route path is defined only once. If you need different behaviors for the same URL:
     - Use a single route with conditional logic inside
     - Use different route paths (e.g., `/collector/dashboard/v2`)
     - Use different HTTP methods (GET vs POST) on the same path

   - If you encounter a `TemplateNotFound` error, make sure the template file exists in the correct location.

## Directory Structure

- `/templates` - HTML templates
  - `/admin` - Admin interface templates
  - `/user` - User interface templates
  - `/collector` - Collector interface templates
- `/static` - Static files (CSS, JS, images)
- `app.py` - Main application file
- `requirements.txt` - Python dependencies

## Development

### Adding New Features

1. Modify the database models in `app.py`
2. Create migration: `flask db migrate -m "Description of changes"`
3. Apply migration: `flask db upgrade`
4. Add routes and views to `app.py`
5. Create or update templates in `/templates`

## Deployment

For production deployment:

1. Use a production WSGI server like Gunicorn
2. Set `DEBUG=False` in app configuration
3. Use an environment variable for `SECRET_KEY`
4. Consider using a PostgreSQL database for production

## License

© 2023 G-TRUCKS. All rights reserved.
