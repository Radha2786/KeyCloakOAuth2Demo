# API Testing Examples

This file contains example requests to test the authentication and authorization system.

## Prerequisites

1. **Keycloak Setup**: Make sure Keycloak is running on http://localhost:8080 with:
   - Realm: `oauth2-demos`
   - Client: `oauth2-authorization-code-flow`
   - Admin user: `admin/admin`

2. **Database Setup**: PostgreSQL running with database `oauth_db`

3. **Application Running**: Spring Boot app running on http://localhost:9876

## Test Sequence

### 1. Health Check (Public)
```bash
curl -X GET http://localhost:9876/api/health
```

### 2. Test Public Endpoint
```bash
curl -X GET http://localhost:9876/api/test/public
```

### 3. Register a New User with Role
```bash
curl -X POST http://localhost:9876/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser1",
    "email": "testuser1@example.com",
    "firstName": "Test",
    "lastName": "User",
    "password": "password123",
    "role": "user"
  }'
```

### 3.1. Register an Employee User
```bash
curl -X POST http://localhost:9876/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "employee1",
    "email": "employee1@company.com",
    "firstName": "John",
    "lastName": "Employee",
    "password": "password123",
    "role": "employee"
  }'
```

Expected Response:
```json
{
  "message": "User registered successfully",
  "userId": "1",
  "success": true
}
```

### 4. Login User
```bash
curl -X POST http://localhost:9876/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser1",
    "password": "password123"
  }'
```

Expected Response:
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 300,
  "scope": "openid profile email",
  "success": true,
  "message": "Login successful"
}
```

### 5. Access Protected Endpoint (Use token from step 4)
```bash
curl -X GET http://localhost:9876/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

### 6. Test Protected Test Endpoint
```bash
curl -X GET http://localhost:9876/api/test/protected \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

### 7. Refresh Token
```bash
curl -X POST http://localhost:9876/api/refresh-token \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN_HERE"
  }'
```

### 8. Test Admin Endpoint (requires admin role)
```bash
curl -X GET http://localhost:9876/api/test/admin \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

**Note**: This will fail unless the user has admin role assigned in Keycloak.

## PowerShell Examples

### Register User (PowerShell)
```powershell
$registerData = @{
    username = "testuser2"
    email = "testuser2@example.com"
    firstName = "Test"
    lastName = "User"
    password = "password123"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:9876/api/register"
  -Method POST `
  -Body $registerData `
  -ContentType "application/json"
```

### Login User (PowerShell)
```powershell
$loginData = @{
    username = "testuser2"
    password = "password123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:9876/api/login" `
  -Method POST `
  -Body $loginData `
  -ContentType "application/json"

$accessToken = $response.accessToken
Write-Host "Access Token: $accessToken"
```

### Access Protected Endpoint (PowerShell)
```powershell
$headers = @{
    "Authorization" = "Bearer $accessToken"
}

Invoke-RestMethod -Uri "http://localhost:9876/api/profile" `
  -Method GET `
  -Headers $headers
```

## Error Cases to Test

### 1. Register with Existing Username
```bash
curl -X POST http://localhost:9876/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser1",
    "email": "newemail@example.com",
    "firstName": "Another",
    "lastName": "User",
    "password": "password123"
  }'
```

Expected: 400 Bad Request with error message

### 2. Register with Invalid Data
```bash
curl -X POST http://localhost:9876/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "te",
    "email": "invalid-email",
    "firstName": "",
    "lastName": "",
    "password": "123"
  }'
```

Expected: 400 Bad Request with validation errors

### 3. Login with Wrong Credentials
```bash
curl -X POST http://localhost:9876/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser1",
    "password": "wrongpassword"
  }'
```

Expected: 401 Unauthorized

### 4. Access Protected Endpoint Without Token
```bash
curl -X GET http://localhost:9876/api/profile
```

Expected: 401 Unauthorized

### 5. Access Protected Endpoint with Invalid Token
```bash
curl -X GET http://localhost:9876/api/profile \
  -H "Authorization: Bearer invalid-token"
```

Expected: 401 Unauthorized

## Database Verification

After registration, you can verify the user was created in PostgreSQL:

```sql
-- Connect to your PostgreSQL database
psql -U postgres -d oauth_db

-- Check users table
SELECT * FROM users;

-- Expected to see the registered user with keycloak_user_id populated
```

## Keycloak Verification

1. Login to Keycloak Admin Console: http://localhost:8080
2. Go to your realm: `oauth2-demos`
3. Navigate to Users
4. You should see the registered user

## Frontend Integration Example (JavaScript)

```javascript
class AuthService {
  constructor() {
    this.baseUrl = 'http://localhost:9876/api';
    this.token = localStorage.getItem('accessToken');
  }

  async register(userData) {
    const response = await fetch(`${this.baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });
    return response.json();
  }

  async login(credentials) {
    const response = await fetch(`${this.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    
    const data = await response.json();
    if (data.success) {
      this.token = data.accessToken;
      localStorage.setItem('accessToken', this.token);
      localStorage.setItem('refreshToken', data.refreshToken);
    }
    return data;
  }

  async getProfile() {
    const response = await fetch(`${this.baseUrl}/profile`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    return response.json();
  }

  async refreshToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    const response = await fetch(`${this.baseUrl}/refresh-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    
    const data = await response.json();
    if (data.success) {
      this.token = data.accessToken;
      localStorage.setItem('accessToken', this.token);
      localStorage.setItem('refreshToken', data.refreshToken);
    }
    return data;
  }

  logout() {
    this.token = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  }
}

// Usage example
const auth = new AuthService();

// Register
auth.register({
  username: 'jsuser',
  email: 'jsuser@example.com',
  firstName: 'JavaScript',
  lastName: 'User',
  password: 'password123'
}).then(result => console.log('Registration:', result));

// Login
auth.login({
  username: 'jsuser',
  password: 'password123'
}).then(result => console.log('Login:', result));

// Get profile
auth.getProfile().then(profile => console.log('Profile:', profile));
```
