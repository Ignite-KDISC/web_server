# SSL/HTTPS Setup for KDISC Igniet API

## Issue Resolved
Fixed CORS errors when accessing the API from the Vercel frontend (`https://ignietkdisc.vercel.app`) due to Chrome's Private Network Access policy.

## Root Cause
- Nginx was configured to use SSL certificates that didn't exist
- Nginx couldn't listen on port 443 (HTTPS)
- All HTTPS requests were failing before reaching the backend
- CORS headers from the Go backend couldn't be sent because connections failed at the SSL/TLS level

## Solution Implemented

### 1. SSL Certificates
Created self-signed SSL certificates (valid for 365 days):
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/api.igniet.kdisc.kerala.gov.in.key \
  -out /etc/ssl/certs/api.igniet.kdisc.kerala.gov.in.crt \
  -subj "/C=IN/ST=Kerala/L=Thiruvananthapuram/O=KDISC/CN=api.igniet.kdisc.kerala.gov.in"
```

**Note:** Since this server is on a private network (10.5.140.241) and not publicly accessible, Let's Encrypt certificates cannot be obtained automatically. The self-signed certificate works for the application needs.

### 2. Nginx Configuration
Updated `/etc/nginx/sites-available/api.igniet.kdisc.kerala.gov.in`:
- Configured HTTP to HTTPS redirect
- Set up SSL/TLS with proper protocols (TLSv1.2, TLSv1.3)
- Proxies all requests to the Go backend on localhost:8080
- Preserves Origin headers for CORS processing

### 3. Backend CORS Support
The Go application already had proper CORS middleware that:
- Allows requests from `https://ignietkdisc.vercel.app`
- Sets `Access-Control-Allow-Private-Network: true` for Chrome's Private Network Access policy
- Handles preflight OPTIONS requests
- Sets appropriate headers for credentials and methods

## Verification
```bash
# Check nginx is listening on port 443
ss -tln | grep :443

# Test CORS preflight
curl -k -I -X OPTIONS "https://api.igniet.kdisc.kerala.gov.in/api/problem-statements" \
  -H "Origin: https://ignietkdisc.vercel.app" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -H "Access-Control-Request-Private-Network: true"
```

## Certificate Renewal
Self-signed certificate expires: February 12, 2027

To renew:
```bash
# Regenerate certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/api.igniet.kdisc.kerala.gov.in.key \
  -out /etc/ssl/certs/api.igniet.kdisc.kerala.gov.in.crt \
  -subj "/C=IN/ST=Kerala/L=Thiruvananthapuram/O=KDISC/CN=api.igniet.kdisc.kerala.gov.in"

# Reload nginx
sudo systemctl reload nginx
```

## Future Improvements
If the server becomes publicly accessible, consider:
1. Getting proper SSL certificates from Let's Encrypt
2. Setting up automatic certificate renewal with certbot
3. Using an internal Certificate Authority for the organization

## Date
Fixed: February 12, 2026
