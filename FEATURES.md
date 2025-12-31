# IGNIET - Innovation Gateway for Next-gen Innovative Engineering & Technology

## Overview
IGNIET is a comprehensive problem statement management system built for educational institutions to collect, track, and manage innovation ideas from students and faculty.

## Tech Stack
- **Frontend**: Next.js 16.1.1 with TypeScript, Tailwind CSS
- **Backend**: Go 1.24 with PostgreSQL
- **Deployment**: Docker Compose

## Features

### Public Features
1. **Problem Statement Submission**
   - Multi-field form for comprehensive problem descriptions
   - File upload support (multiple documents)
   - Email validation
   - Contact number validation (10 digits)
   - Real-time form validation
   - Automatic reference ID generation
   - Email acknowledgment on submission

### Admin Features
1. **Authentication & Security**
   - JWT-based authentication
   - Password reset flow with token-based email links
   - Secure admin login

2. **Dashboard**
   - Statistics overview (Total, Active, Under Review, Accepted, Rejected)
   - Recent submissions list
   - Comprehensive problem statements list with pagination (10 per page)

3. **Problem Statement Management**
   - View full problem statement details
   - Update submission status (Active/PoC/Closed)
   - Update review decision (Under Review/Accepted/Rejected)
   - Assign to reviewer
   - View uploaded documents

4. **Search & Filtering**
   - Search by reference ID, title, submitter name, department
   - Filter by submission status
   - Filter by review decision
   - Filter by department
   - Date range filtering (start and end date)
   - Clear all filters button

5. **Internal Remarks**
   - Add internal notes/remarks to problem statements
   - View all remarks with timestamp and author
   - Delete remarks
   - Remarks are admin-only and not visible to submitters

6. **Export**
   - Export all problem statements to CSV
   - Includes all fields: reference ID, submitter, department, title, description, status, decision

7. **Audit Logging**
   - Automatic logging of all admin actions
   - Tracks: review decision changes, status updates, reviewer assignments
   - Stores admin email, timestamp, action type, and details

## Database Schema

### Tables
1. `problem_statements` - Main problem data
2. `problem_documents` - Uploaded files metadata
3. `admin_users` - Admin accounts with hashed passwords
4. `internal_remarks` - Admin-only notes
5. `audit_logs` - All admin action logs
6. `password_reset_tokens` - Password reset tokens
7. `export_logs` - Export activity tracking
8. `submission_status_enum` - Status values (Active, PoC, Closed)
9. `review_decision_enum` - Decision values (Under Review, Accepted, Rejected)

## API Endpoints

### Public Endpoints
- `POST /api/problem-statements` - Submit problem statement with files

### Auth Endpoints
- `POST /api/admin/register` - Create admin account
- `POST /api/admin/login` - Admin login (returns JWT)
- `POST /api/auth/request-password-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token

### Protected Admin Endpoints
- `GET /api/admin/dashboard` - Dashboard data and statistics
- `GET /api/admin/problem-statements` - Paginated list
- `GET /api/admin/problem-statement` - Single problem details
- `GET /api/admin/problem-documents` - Documents for a problem
- `POST /api/admin/update-review-decision` - Update decision
- `POST /api/admin/update-submission-status` - Update status
- `POST /api/admin/assign-reviewer` - Assign to reviewer
- `GET /api/admin/internal-remarks` - Get remarks for problem
- `POST /api/admin/add-internal-remark` - Add remark
- `POST /api/admin/delete-internal-remark` - Delete remark
- `GET /api/admin/export-csv` - Export all problems to CSV
- `GET /uploads/:filename` - Serve uploaded files

## Environment Setup

### Development
Create `.env.local` in `web_client/`:
```
NEXT_PUBLIC_API_URL=http://localhost:8080
```

Create `.env.production` in `web_client/`:
```
NEXT_PUBLIC_API_URL=https://your-production-api.com
```

### Database
PostgreSQL connection configured in `docker-compose.yml`:
- Database: `ignite`
- User: `postgres`
- Password: `postgres`
- Port: 5432

## Running the Application

### Development with Docker Compose
```bash
docker-compose up --build
```

Services:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8080
- PostgreSQL: localhost:5432

### Production
```bash
docker-compose -f docker-compose.yml up -d
```

## File Upload
- Uploaded files stored in `./uploads` directory
- Mapped to `/app/uploads` in containers
- Files served via `/uploads/:filename` endpoint
- Supports multiple file types (PDF, DOC, DOCX, XLS, XLSX, images)

## Security Features
- Password hashing with bcrypt
- JWT authentication for admin routes
- CORS enabled for cross-origin requests
- Token expiration (24 hours for password reset)
- Input validation on both frontend and backend

## Future Enhancements
- SMTP email integration for acknowledgments and notifications
- Advanced analytics and reporting
- Role-based access control (Super Admin, Reviewer, Viewer)
- Real-time notifications
- File preview for documents
- Bulk operations (approve/reject multiple)
- Advanced search with Elasticsearch
- API rate limiting
- Two-factor authentication

## Contributing
1. Fork the repository
2. Create feature branch
3. Commit changes with meaningful messages
4. Push to branch
5. Create Pull Request

## License
Proprietary - All rights reserved

## Contact
For questions or support, contact the IGNIET development team.
