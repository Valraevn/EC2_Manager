# EC2 Instance Manager

A web application for managing EC2 instances with features like:
- User authentication
- Start/Stop EC2 instances
- IP/DNS management
- Auto-shutdown on inactivity
- SSH session monitoring

## Setup
docker-compose up --build


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
