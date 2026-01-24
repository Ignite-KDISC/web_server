# Environment Configuration

## Database Configuration
```
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=ignite
```

## Server Configuration
```
PORT=8080
```

## JWT Configuration (optional)
```
JWT_SECRET=your-secret-key-here
JWT_EXPIRY=24h
```

## Email Configuration (future)
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=noreply@igniet.gov.in
```

## File Upload
```
UPLOAD_DIR=/app/uploads
MAX_FILE_SIZE=10485760  # 10MB in bytes
```

## Development vs Production
- Development: Use docker-compose.dev.yml
- Production: Use docker-compose.yml

## Security Notes
- Never commit .env files to version control
- Rotate JWT secrets regularly
- Use strong database passwords in production
- Enable HTTPS in production
- Implement rate limiting
