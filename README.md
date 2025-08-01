# Spring Boot Keycloak OAuth2 Demo

This is a complete implementation of user authentication and authorization using Spring Boot, Keycloak, PostgreSQL, and Lombok.

## Features

- ✅ User registration without direct Keycloak access
- ✅ Secure backend-to-Keycloak communication using admin token
- ✅ User login with JWT token retrieval
- ✅ Token-based authentication for protected endpoints
- ✅ Role-based access control
- ✅ PostgreSQL database integration
- ✅ Comprehensive error handling
- ✅ CORS configuration for frontend integration

## Architecture

```
Frontend → Spring Boot Backend → Keycloak
                ↓
         PostgreSQL Database
```

### User Registration Flow
1. Frontend calls `POST /api/register`
2. Backend validates input and checks for existing users
3. Backend uses admin token to create user in Keycloak
4. Backend stores user data in PostgreSQL
5. User is registered in both systems securely

### User Login Flow
1. Frontend calls `POST /api/login`
2. Backend forwards credentials to Keycloak
3. Keycloak returns JWT access token
4. Frontend uses token for subsequent API calls

## Setup

### Prerequisites
1. Java 17+
2. Maven 3.6+
3. PostgreSQL 12+
4. Keycloak 20+

### Keycloak Configuration

1. **Start Keycloak**
   ```bash
   # Docker approach
   docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
   ```

2. **Create Realm**
   - Login to Keycloak Admin Console: http://localhost:8080
   - Create realm: `oauth2-demos`

3. **Create Client**
   - Client ID: `oauth2-authorization-code-flow`
   - Client authentication: ON
   - Authorization: OFF
   - Valid redirect URIs: `http://localhost:9876/*`
   - Web origins: `http://localhost:9876`

4. **Get Client Secret**
   - Go to Clients → oauth2-authorization-code-flow → Credentials
   - Copy the secret and update `application.properties`

### Database Configuration

1. **Create PostgreSQL Database**
   ```sql
   CREATE DATABASE oauth_db;
   ```

2. **Update Database Credentials**
   Edit `src/main/resources/application.properties`:
   ```properties
   spring.datasource.username=your_username
   spring.datasource.password=your_password
   ```

### Application Configuration

Update the following in `application.properties`:

```properties
# Keycloak Admin Configuration
keycloak.admin.username=admin
keycloak.admin.password=admin
keycloak.admin.client-secret=YOUR_CLIENT_SECRET

# Database Configuration
spring.datasource.username=YOUR_DB_USERNAME
spring.datasource.password=YOUR_DB_PASSWORD
```

## Running the Application

```bash
mvn clean install
mvn spring-boot:run
```

The application will start on: http://localhost:9876

## API Endpoints

### Public Endpoints

#### User Registration
```http
POST /api/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "password": "securePassword123"
}
```

#### User Login
```http
POST /api/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "securePassword123"
}
```

Response:
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

#### Token Refresh
```http
POST /api/refresh-token
Content-Type: application/json

{
  "refreshToken": "your_refresh_token"
}
```

#### Health Check
```http
GET /api/health
```

### Protected Endpoints (Require JWT Token)

#### Get User Profile
```http
GET /api/profile
Authorization: Bearer your_access_token
```

#### Test Endpoints
```http
GET /api/test/public        # No authentication required
GET /api/test/protected     # Requires valid JWT token
GET /api/test/admin         # Requires admin role
```

### Admin Endpoints

#### Get All Users (Admin Only)
```http
GET /api/admin/users
Authorization: Bearer admin_access_token
```

## Usage Examples

### 1. Register a New User

```bash
curl -X POST http://localhost:9876/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "password": "password123"
  }'
```

### 2. Login

```bash
curl -X POST http://localhost:9876/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### 3. Access Protected Endpoint

```bash
curl -X GET http://localhost:9876/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Security Features

### Admin Token Security
- Admin credentials are stored securely in application.properties
- Admin token is never exposed to frontend
- Backend handles all Keycloak admin operations internally

### JWT Token Validation
- Automatic token validation using Spring Security OAuth2 Resource Server
- Supports role-based access control (RBAC)
- Scope-based authorization

### User Registration Security
- Input validation using Bean Validation
- Duplicate username/email prevention
- Secure password handling (passwords are sent to Keycloak, not stored locally)

## Role Management

Users created via the Admin API do NOT have admin privileges unless explicitly assigned. To assign admin roles:

1. Go to Keycloak Admin Console
2. Navigate to Users → Select User → Role Mapping
3. Assign desired roles (realm roles or client roles)

## Troubleshooting

### Common Issues

1. **Admin Token Not Working**
   - Verify Keycloak admin credentials
   - Check if Keycloak is running on correct port
   - Ensure master realm is accessible

2. **JWT Token Validation Fails**
   - Verify issuer-uri in application.properties
   - Check if realm name matches exactly
   - Ensure Keycloak realm is active

3. **Database Connection Issues**
   - Verify PostgreSQL is running
   - Check database credentials
   - Ensure database exists

### Logs

Enable debug logging for OAuth2:
```properties
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.security.oauth2=DEBUG
```

## Frontend Integration

This backend is designed to work with any frontend framework. Example JavaScript usage:

```javascript
// Register user
const registerResponse = await fetch('http://localhost:9876/api/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'johndoe',
    email: 'john@example.com',
    firstName: 'John',
    lastName: 'Doe',
    password: 'password123'
  })
});

// Login user
const loginResponse = await fetch('http://localhost:9876/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'johndoe',
    password: 'password123'
  })
});

const { accessToken } = await loginResponse.json();

// Access protected endpoint
const profileResponse = await fetch('http://localhost:9876/api/profile', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```

## Production Considerations

1. **Security**
   - Use environment variables for sensitive configuration
   - Enable HTTPS in production
   - Configure proper CORS origins
   - Use strong admin passwords

2. **Performance**
   - Configure connection pooling for database
   - Implement caching for frequently accessed data
   - Use Redis for session storage in distributed environments

3. **Monitoring**
   - Add health checks and metrics
   - Implement proper logging
   - Set up monitoring dashboards

## License

This project is for demonstration purposes. Use it as a reference for your own implementations.
