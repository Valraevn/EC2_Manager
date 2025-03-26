# EC2 Instance Manager

A web application for managing EC2 instances with features like:
- User authentication
- Start/Stop EC2 instances
- IP/DNS management
- Auto-shutdown on inactivity
- SSH session monitoring

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Populate `.env` file with the following variables:
```
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=your_region
FLASK_SECRET_KEY=your_secret_key
```

3. Run it
   docker-compose up --build
```

## Features

- User authentication system
- EC2 instance management (start/stop)
- Real-time instance status monitoring
- Auto-shutdown after 30 minutes of inactivity
- SSH session monitoring
- IP/DNS management

## Security Notes

- Store AWS credentials securely
- Use IAM roles with minimal required permissions
- Enable HTTPS in production
- Regularly rotate credentials 
