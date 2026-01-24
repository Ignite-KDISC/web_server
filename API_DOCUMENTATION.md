# API Documentation - IGNIET Backend

Base URL: `http://localhost:8080` (development)

## Authentication
Most admin endpoints require JWT authentication via Bearer token in Authorization header:
```
Authorization: Bearer <jwt_token>
```

---

## Public Endpoints

### Submit Problem Statement
**POST** `/api/problem-statements`

**Content-Type:** `multipart/form-data`

**Fields:**
- `submitter_name` (required)
- `department_name` (required)
- `designation` (optional)
- `contact_number` (required, 10 digits)
- `email` (required)
- `title` (required)
- `problem_description` (required)
- `current_challenges` (optional)
- `expected_outcome` (optional)
- `documents` (optional, multiple files)

**Response:**
```json
{
  "success": true,
  "message": "Problem statement submitted successfully",
  "reference_id": "IGNIET-2024-0001",
  "data": { ...problem_statement_object },
  "files": [ ...uploaded_files ]
}
```

---

## Auth Endpoints

### Admin Registration
**POST** `/api/admin/register`

**Request Body:**
```json
{
  "name": "Admin Name",
  "email": "admin@example.com",
  "password": "securepassword123"
}
```

### Admin Login
**POST** `/api/admin/login`

**Request Body:**
```json
{
  "email": "admin@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "token": "jwt_token_here",
  "admin": {
    "id": 1,
    "email": "admin@example.com",
    "name": "Admin Name"
  }
}
```

### Request Password Reset
**POST** `/api/auth/request-password-reset`

**Request Body:**
```json
{
  "email": "admin@example.com"
}
```

### Reset Password
**POST** `/api/auth/reset-password`

**Request Body:**
```json
{
  "token": "reset_token_from_email",
  "new_password": "newpassword123"
}
```

---

## Protected Admin Endpoints

### Get Dashboard Data
**GET** `/api/admin/dashboard`

**Headers:** Authorization Bearer token required

**Response:**
```json
{
  "success": true,
  "admin": {
    "id": "1",
    "email": "admin@example.com"
  },
  "statistics": {
    "total_problems": 100,
    "active_problems": 50,
    "under_review": 30,
    "accepted": 15,
    "rejected": 5
  },
  "recent_submissions": [ ...problem_statements ]
}
```

### List Problem Statements (Paginated)
**GET** `/api/admin/problem-statements?page=1&limit=10`

**Query Parameters:**
- `page` (default: 1)
- `limit` (default: 10, max: 100)

### Get Single Problem Statement
**GET** `/api/admin/problem-statement?id=123`

### Get Problem Documents
**GET** `/api/admin/problem-documents?problem_id=123`

### Update Review Decision
**POST** `/api/admin/update-review-decision`

**Request Body:**
```json
{
  "id": 123,
  "review_decision": "Accepted"
}
```

Valid values: `Under Review`, `Accepted`, `Rejected`

### Update Submission Status
**POST** `/api/admin/update-submission-status`

**Request Body:**
```json
{
  "id": 123,
  "submission_status": "PoC"
}
```

Valid values: `Active`, `PoC`, `Closed`

### Assign Reviewer
**POST** `/api/admin/assign-reviewer`

**Request Body:**
```json
{
  "id": 123,
  "assigned_reviewer": "reviewer@example.com"
}
```

### Get Internal Remarks
**GET** `/api/admin/internal-remarks?problem_id=123`

### Add Internal Remark
**POST** `/api/admin/add-internal-remark`

**Request Body:**
```json
{
  "problem_statement_id": 123,
  "remark_text": "This needs further review",
  "created_by": "admin@example.com"
}
```

### Delete Internal Remark
**POST** `/api/admin/delete-internal-remark`

**Request Body:**
```json
{
  "id": 456
}
```

### Export to CSV
**GET** `/api/admin/export-csv`

**Response:** CSV file download

---

## File Serving

### Get Uploaded File
**GET** `/uploads/:filename`

Example: `http://localhost:8080/uploads/abc123_document.pdf`

---

## Error Responses

All endpoints return appropriate HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (invalid/missing token)
- `404` - Not Found
- `500` - Internal Server Error

Error Response Format:
```json
{
  "error": "Error message here"
}
```

Or plain text error messages.

---

## Rate Limiting
Currently not implemented. Recommended for production.

## CORS
CORS is enabled for all origins in development. Configure appropriately for production.
