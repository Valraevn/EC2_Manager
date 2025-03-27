# EC2 Manager with Discord Bot Integration

A web-based EC2 instance manager with Discord bot integration that allows users to manage their AWS EC2 instances through both a web interface and Discord commands.

## Features

### Web Interface
- Secure login system with user management
- Admin and regular user roles
- Real-time instance status monitoring
- AWS credentials management
- Instance creation with customizable settings
- Start/Stop/Delete instance controls
- Global region support

### Discord Bot Integration
- Easy-to-use commands for managing EC2 instances
- Automatic user creation upon first interaction
- SSH key management for secure instance access
- One instance per user policy
- Admin commands for instance management

## Discord Commands

### User Commands
- `!start <ssh_public_key>` - Start a new EC2 instance with your SSH key
- `!stop` - Stop your running instance
- `!delete` - Delete your stopped instance
- `!ip` - Get your instance's IP address and state
- `!ec2help` - Show help message with available commands

### Admin Commands
- `!admin-delete <instance_id>` - Delete any instance (admin only)

## Supported SSH Key Types
- RSA (starts with 'ssh-rsa')
- Ed25519 (starts with 'ssh-ed25519')
- ECDSA (starts with 'ecdsa-sha2-nistp256/384/521')

## Instance Management Rules
1. Each non-admin user can have only one instance at a time
2. Users must delete their stopped instance before creating a new one
3. Instances are automatically stopped after 60 minutes of inactivity
4. Users can only manage their own instances
5. Admins can view and manage all instances

## Setup

### Prerequisites
- Docker and Docker Compose
- AWS Account with EC2 permissions
- Discord Bot Token
- Python 3.8+

### Environment Variables
Create a `.env` file with the following variables:
```env
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
DISCORD_TOKEN=your_discord_bot_token
ALLOWED_CHANNEL_ID=your_discord_channel_id
FLASK_SECRET_KEY=your_flask_secret_key
```

### Installation
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd ec2_manager
   ```

2. Build and start the containers:
   ```bash
   docker-compose up --build
   ```

3. Access the web interface at `http://localhost:5000`

### Default Credentials
- Username: admin
- Password: admin
- **Important**: Change the default password after first login!

## Instance Specifications
- Instance Type: t2.micro
- OS: Amazon Linux 2023
- Security Group: Automatically created with SSH (port 22) access
- SSH User: ec2-user

## Security Features
- Password hashing for user accounts
- AWS credentials validation
- Instance ownership verification
- Role-based access control
- SSH key validation
- Secure instance tagging

## Monitoring and Automation
- Automatic instance status monitoring
- Inactivity detection and auto-shutdown
- Real-time instance state updates
- Background task management

## Error Handling
- AWS credential validation
- SSH key format verification
- Instance state verification
- User permission checks
- Comprehensive error messages

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
[Your License Here] 