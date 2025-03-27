from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import boto3
import os
from dotenv import load_dotenv
import psutil
import threading
import time
import json
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User data file
USERS_FILE = 'data/users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users_data):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users_data, f, indent=4)

# Load users from file
users = load_users()

# AWS Configuration
def get_aws_credentials():
    aws_access_key = session.get('aws_access_key', os.getenv('AWS_ACCESS_KEY_ID'))
    aws_secret_key = session.get('aws_secret_key', os.getenv('AWS_SECRET_ACCESS_KEY'))
    aws_region = session.get('aws_region', os.getenv('AWS_REGION', 'us-east-1'))
    
    # Only log credentials debug info when there's an issue
    if not aws_access_key or not aws_secret_key:
        print("\nAWS Credential Debug:")
        print(f"Access Key from session: {'Present' if session.get('aws_access_key') else 'Not present'}")
        print(f"Access Key from env: {'Present' if os.getenv('AWS_ACCESS_KEY_ID') else 'Not present'}")
        print(f"Secret Key from session: {'Present' if session.get('aws_secret_key') else 'Not present'}")
        print(f"Secret Key from env: {'Present' if os.getenv('AWS_SECRET_ACCESS_KEY') else 'Not present'}")
        print(f"Region being used: {aws_region}")
    
    if not aws_access_key or not aws_secret_key:
        raise Exception("AWS credentials not configured. Please set up your AWS credentials in the settings.")
    
    return aws_access_key, aws_secret_key, aws_region

def get_ec2_client(region=None):
    aws_access_key, aws_secret_key, aws_region = get_aws_credentials()
    if not all([aws_access_key, aws_secret_key]):
        raise Exception("AWS credentials not configured. Please set up your AWS credentials in the settings.")
    
    # If region is specified, use it; otherwise use the configured region
    region = region or aws_region
    if region == 'global':
        # For global view, default to us-east-1 as it's the most common region
        region = 'us-east-1'
    
    return boto3.client('ec2',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region
    )

def get_all_regions():
    aws_access_key, aws_secret_key, _ = get_aws_credentials()
    if not all([aws_access_key, aws_secret_key]):
        raise Exception("AWS credentials not configured")
    
    # Use us-east-1 to get all regions
    ec2 = boto3.client('ec2',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name='us-east-1'
    )
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    return regions

def get_instances_for_user(user_id, include_all=False):
    """Get EC2 instances for a specific user or all instances for admin"""
    try:
        ec2_client = get_ec2_client()
        response = ec2_client.describe_instances()
        
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Get instance tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                
                # Include instance if it belongs to the user or if admin requesting all
                if include_all or tags.get('UserID') == str(user_id):
                    # Get user info if admin view
                    user_info = ''
                    if include_all:
                        user_id_tag = tags.get('UserID')
                        discord_id_tag = tags.get('DiscordID')
                        if user_id_tag:
                            for user_data in users.values():
                                if str(user_data['id']) == user_id_tag:
                                    user_info = f"{user_data['username']}"
                                    if user_data.get('discord_username'):
                                        user_info = f"{user_data['discord_username']}"
                                    elif user_data.get('discord_id'):
                                        user_info += f" (Discord ID: {user_data['discord_id']})"
                                    break
                    
                    # Format the timestamp
                    launch_time = instance.get('LaunchTime', '')
                    if launch_time:
                        launch_time = launch_time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    instances.append({
                        'instance_id': instance['InstanceId'],
                        'name': tags.get('Name', 'Unnamed'),
                        'state': instance['State']['Name'],
                        'public_ip': instance.get('PublicIpAddress') or tags.get('LastKnownIP'),
                        'region': session.get('aws_region', 'us-east-1'),
                        'last_activity': launch_time,
                        'owner': user_info if include_all else ''
                    })
        
        return instances
    except Exception as e:
        print(f"Error getting instances: {str(e)}")
        return []

def get_instance_by_id(instance_id, user_id):
    try:
        aws_region = session.get('aws_region', os.getenv('AWS_REGION'))
        if aws_region == 'global':
            # Try all regions
            regions = get_all_regions()
            for region in regions:
                ec2 = get_ec2_client(region)
                try:
                    response = ec2.describe_instances(InstanceIds=[instance_id])
                    if response['Reservations']:
                        instance = response['Reservations'][0]['Instances'][0]
                        return instance, region
                except:
                    continue
        else:
            # Try specific region
            ec2 = get_ec2_client()
            response = ec2.describe_instances(InstanceIds=[instance_id])
            if response['Reservations']:
                instance = response['Reservations'][0]['Instances'][0]
                return instance, aws_region
    except Exception as e:
        print(f"Error getting instance {instance_id}: {str(e)}")
    return None, None

# Models
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']
        self.instances = user_data.get('instances', [])
        self.role = user_data.get('role', 'user')  # 'admin' or 'user'
        self.discord_id = user_data.get('discord_id')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    @staticmethod
    def get(user_id):
        for user_data in users.values():
            if user_data['id'] == user_id:
                return User(user_data)
        return None

class Instance:
    def __init__(self, instance_data, region):
        self.id = instance_data.get('InstanceId')
        self.instance_id = instance_data.get('InstanceId')
        self.name = next((tag['Value'] for tag in instance_data.get('Tags', []) if tag['Key'] == 'Name'), 'Unnamed')
        self.public_ip = instance_data.get('PublicIpAddress')
        self.state = instance_data['State']['Name']
        self.last_activity = datetime.utcnow()
        self.region = region
        self.instance_type = instance_data.get('InstanceType')
        launch_time = instance_data.get('LaunchTime')
        self.launch_time = launch_time.strftime('%Y-%m-%d %H:%M:%S') if launch_time else ''

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

def get_aws_credentials_from_env():
    """Get AWS credentials from environment variables only"""
    aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')
    
    if not aws_access_key or not aws_secret_key:
        raise Exception("AWS credentials not configured")
    
    return aws_access_key, aws_secret_key, aws_region

def get_ec2_client_from_env(region=None):
    """Get EC2 client using environment variables only"""
    try:
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        aws_region = region or os.getenv('AWS_REGION', 'us-east-1')
        
        if not aws_access_key or not aws_secret_key:
            raise Exception("AWS credentials not configured")
        
        # Always use a specific region, never 'global'
        if aws_region == 'global':
            aws_region = 'us-east-1'
            
        print(f"Creating EC2 client with region: {aws_region}")
        
        return boto3.client('ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        )
    except Exception as e:
        print(f"Error creating EC2 client: {str(e)}")
        raise

def check_ssh_sessions():
    """Check SSH sessions in background thread"""
    with app.app_context():
        while True:
            try:
                # Get all instances for all users
                aws_region = os.getenv('AWS_REGION', 'us-east-1')
                if aws_region == 'global':
                    regions = get_all_regions()
                    for region in regions:
                        try:
                            ec2 = get_ec2_client_from_env(region)
                            response = ec2.describe_instances()
                            # Process instances...
                        except Exception as region_error:
                            print(f"Error checking region {region}: {str(region_error)}")
                else:
                    ec2 = get_ec2_client_from_env()
                    response = ec2.describe_instances()
                    # Process instances...
            except Exception as e:
                print(f"Error in SSH session check: {str(e)}")
            time.sleep(60)  # Check every minute

def check_inactive_instances():
    """Check for and stop instances that have been inactive for 60 minutes"""
    with app.app_context():
        while True:
            try:
                # Get all instances for all users
                aws_region = os.getenv('AWS_REGION', 'us-east-1')
                if aws_region == 'global':
                    regions = get_all_regions()
                    for region in regions:
                        ec2 = get_ec2_client_from_env(region)
                        response = ec2.describe_instances()
                        process_inactive_instances(response, region)
                else:
                    ec2 = get_ec2_client_from_env()
                    response = ec2.describe_instances()
                    process_inactive_instances(response, aws_region)
            except Exception as e:
                print(f"Error checking inactive instances: {str(e)}")
            time.sleep(60)  # Check every minute

def process_inactive_instances(response, region):
    """Process instances and stop those that have been inactive for 60 minutes"""
    current_time = datetime.utcnow()
    inactive_threshold = timedelta(minutes=60)
    
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            # Skip instances that aren't running
            if instance['State']['Name'] != 'running':
                continue
                
            # Get instance tags
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            
            # Get last activity time from tags
            last_activity_str = tags.get('LastActivity')
            if not last_activity_str:
                continue
                
            try:
                last_activity = datetime.strptime(last_activity_str, '%Y-%m-%d %H:%M:%S')
                if current_time - last_activity > inactive_threshold:
                    # Stop the instance
                    ec2 = get_ec2_client(region)
                    ec2.stop_instances(InstanceIds=[instance['InstanceId']])
                    print(f"Stopped inactive instance {instance['InstanceId']}")
            except Exception as e:
                print(f"Error processing instance {instance['InstanceId']}: {str(e)}")

def update_instance_activity(instance_id, region):
    """Update the LastActivity tag for an instance"""
    try:
        ec2 = get_ec2_client(region)
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'LastActivity', 'Value': current_time}]
        )
    except Exception as e:
        print(f"Error updating instance activity: {str(e)}")

# Routes
@app.route('/')
@login_required
def index():
    try:
        # Test AWS credentials
        get_ec2_client()
    except Exception as e:
        flash(f'AWS credentials not configured: {str(e)}', 'warning')
        return redirect(url_for('settings'))
    
    # Get instances based on user role
    is_admin = current_user.is_admin()
    user_instances = get_instances_for_user(current_user.id, include_all=is_admin)
    return render_template('index.html', instances=user_instances, is_admin=is_admin)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = users.get(username)
        if user_data:
            user = User(user_data)
            if user.check_password(password):
                login_user(user)
                return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def user_management():
    return render_template('users.html', users=users.values())

@app.route('/user', methods=['POST'])
@login_required
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Username and password are required', 'danger')
        return redirect(url_for('user_management'))
    
    if username in users:
        flash('Username already exists', 'danger')
        return redirect(url_for('user_management'))
    
    # Generate a new user ID
    new_id = max([user['id'] for user in users.values()], default=0) + 1
    
    # Create new user with hashed password
    users[username] = {
        'id': new_id,
        'username': username,
        'password_hash': generate_password_hash(password),
        'instances': [],
        'role': 'user'
    }
    
    # Save to file
    save_users(users)
    
    flash('User added successfully', 'success')
    return redirect(url_for('user_management'))

@app.route('/user/<username>', methods=['DELETE'])
@login_required
def delete_user(username):
    if username not in users:
        return jsonify({'status': 'error', 'message': 'User not found'})
    
    # Don't allow deleting the last user
    if len(users) <= 1:
        return jsonify({'status': 'error', 'message': 'Cannot delete the last user'})
    
    del users[username]
    save_users(users)
    
    return jsonify({'status': 'success'})

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    aws_access_key = session.get('aws_access_key', os.getenv('AWS_ACCESS_KEY_ID', ''))
    aws_secret_key = session.get('aws_secret_key', os.getenv('AWS_SECRET_ACCESS_KEY', ''))
    aws_region = session.get('aws_region', os.getenv('AWS_REGION', 'us-east-1'))
    return render_template('settings.html', 
                         aws_access_key=aws_access_key,
                         aws_secret_key=aws_secret_key,
                         aws_region=aws_region)

@app.route('/save_settings', methods=['POST'])
@login_required
def save_settings():
    aws_access_key = request.form.get('aws_access_key')
    aws_secret_key = request.form.get('aws_secret_key')
    aws_region = request.form.get('aws_region')
    
    if not all([aws_access_key, aws_secret_key, aws_region]):
        flash('All AWS settings are required', 'danger')
        return redirect(url_for('settings'))
    
    try:
        # Test the credentials before saving
        test_client = boto3.client('sts',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region if aws_region != 'global' else 'us-east-1'
        )
        
        # Try to get caller identity to verify credentials
        test_client.get_caller_identity()
        
        # Save to environment variables first (for background tasks)
        os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_key
        os.environ['AWS_REGION'] = aws_region if aws_region != 'global' else 'us-east-1'
        
        # Then save to session
        session.permanent = True
        session['aws_access_key'] = aws_access_key
        session['aws_secret_key'] = aws_secret_key
        session['aws_region'] = aws_region
        
        flash('AWS settings saved successfully', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        error_message = str(e)
        if 'InvalidClientTokenId' in error_message:
            error_message = 'Invalid AWS Access Key ID'
        elif 'SignatureDoesNotMatch' in error_message:
            error_message = 'Invalid AWS Secret Access Key'
        flash(f'Error validating AWS credentials: {error_message}', 'danger')
        return redirect(url_for('settings'))

@app.route('/instance/<instance_id>/start')
@login_required
def start_instance(instance_id):
    try:
        instance, region = get_instance_by_id(instance_id, current_user.id)
        if not instance:
            print(f"Instance {instance_id} not found")
            return jsonify({'status': 'error', 'message': 'Instance not found'})
        
        print(f"Starting instance {instance_id} in region {region}")
        ec2 = get_ec2_client(region)
        response = ec2.start_instances(InstanceIds=[instance_id])
        print(f"Start response: {response}")
        
        # Update the last activity time
        update_instance_activity(instance_id, region)
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error starting instance {instance_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/instance/<instance_id>/stop')
@login_required
def stop_instance(instance_id):
    instance, region = get_instance_by_id(instance_id, current_user.id)
    if not instance:
        return jsonify({'status': 'error', 'message': 'Instance not found'})
    
    try:
        ec2 = get_ec2_client(region)
        ec2.stop_instances(InstanceIds=[instance_id])
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/instance/<instance_id>/status')
@login_required
def instance_status(instance_id):
    instance, region = get_instance_by_id(instance_id, current_user.id)
    if not instance:
        return jsonify({'status': 'error', 'message': 'Instance not found'})
    
    try:
        ec2 = get_ec2_client(region)
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if response['Reservations']:
            instance = response['Reservations'][0]['Instances'][0]
            # Update the last activity time for running instances
            if instance['State']['Name'] == 'running':
                update_instance_activity(instance_id, region)
            return jsonify({
                'state': instance['State']['Name'],
                'public_ip': instance.get('PublicIpAddress')
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/add_instance', methods=['POST'])
@login_required
def add_instance():
    name = request.form.get('name')
    instance_id = request.form.get('instance_id')
    
    if not name or not instance_id:
        flash('Name and Instance ID are required', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Verify the instance exists and get its details
        ec2 = get_ec2_client()
        response = ec2.describe_instances(InstanceIds=[instance_id])
        
        if not response['Reservations']:
            flash('Instance not found in AWS', 'danger')
            return redirect(url_for('index'))
            
        instance = response['Reservations'][0]['Instances'][0]
        
        # Add UserID tag to the instance
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'UserID', 'Value': str(current_user.id)},
                {'Key': 'Name', 'Value': name}
            ]
        )
        
        flash('Instance added successfully', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        flash(f'Error adding instance: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/get_key_pairs')
@login_required
def get_key_pairs():
    try:
        ec2 = get_ec2_client()
        response = ec2.describe_key_pairs()
        return jsonify([{
            'name': key['KeyName'],
            'id': key.get('KeyPairId', key['KeyName'])
        } for key in response['KeyPairs']])
    except Exception as e:
        return jsonify([])

@app.route('/get_security_groups')
@login_required
def get_security_groups():
    try:
        ec2 = get_ec2_client()
        response = ec2.describe_security_groups()
        return jsonify([{
            'id': sg['GroupId'],
            'name': sg['GroupName'],
            'description': sg['Description']
        } for sg in response['SecurityGroups']])
    except Exception as e:
        return jsonify([])

@app.route('/create_instance', methods=['POST'])
@login_required
def create_instance():
    try:
        instance_name = request.form.get('instance_name')
        ami_id = request.form.get('ami_id')
        instance_type = request.form.get('instance_type')
        key_name = request.form.get('key_name')
        security_group = request.form.get('security_group')
        
        # Handle custom AMI ID
        if ami_id == 'custom':
            ami_id = request.form.get('custom_ami')
        
        if not all([instance_name, ami_id, instance_type, key_name, security_group]):
            flash('All fields are required', 'danger')
            return redirect(url_for('index'))
        
        ec2 = get_ec2_client()
        
        # Create a single instance
        response = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            SecurityGroupIds=[security_group],
            MinCount=1,
            MaxCount=1,  # Explicitly set to 1 to ensure only one instance is created
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': instance_name},
                    {'Key': 'UserID', 'Value': str(current_user.id)}
                ]
            }]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        flash(f'Instance {instance_id} is being created', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        flash(f'Error creating instance: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/get_amis')
@login_required
def get_amis():
    try:
        ec2 = get_ec2_client()
        
        # Get Amazon Linux 2023 AMI
        al2023 = ec2.describe_images(
            Filters=[
                {'Name': 'name', 'Values': ['al2023-ami-2023.*-x86_64']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'owner-alias', 'Values': ['amazon']}
            ],
            Owners=['amazon']
        )
        
        # Get Ubuntu 22.04 LTS AMI
        ubuntu = ec2.describe_images(
            Filters=[
                {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'owner-alias', 'Values': ['amazon']}
            ],
            Owners=['099720109477']  # Canonical's AWS account ID
        )
        
        # Get Windows Server 2022 AMI
        windows = ec2.describe_images(
            Filters=[
                {'Name': 'name', 'Values': ['Windows_Server-2022-English-Full-Base-*']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'owner-alias', 'Values': ['amazon']}
            ],
            Owners=['amazon']
        )
        
        # Sort by creation date and get the latest
        def get_latest(images):
            if not images['Images']:
                return None
            latest = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
            return {
                'id': latest['ImageId'],
                'name': latest['Name'],
                'description': latest.get('Description', latest['Name'])
            }
        
        amis = {
            'amazon_linux': get_latest(al2023),
            'ubuntu': get_latest(ubuntu),
            'windows': get_latest(windows)
        }
        
        return jsonify(amis)
    except Exception as e:
        print(f"Error fetching AMIs: {str(e)}")
        return jsonify({})

# Admin API endpoints for Discord bot
@app.route('/api/start/<discord_user>', methods=['GET', 'POST'])
def api_start_instance(discord_user):
    try:
        print(f"\nReceived instance creation request for Discord user: {discord_user}")
        # Get Discord username from request
        discord_username = None
        if request.method == 'POST':
            data = request.get_json()
            discord_username = data.get('discord_username') if data else None
        
        # Get or create user
        user_data = get_or_create_discord_user(discord_user, discord_username)
        if not user_data:
            print("Failed to get/create user")
            return jsonify({'status': 'error', 'message': 'User not found'})

        # Get SSH key from request for POST method
        ssh_key = None
        if request.method == 'POST':
            data = request.get_json()
            ssh_key = data.get('ssh_key') if data else None

        if not ssh_key:
            print("No SSH key provided")
            return jsonify({'status': 'error', 'message': 'SSH public key is required'})

        # Validate SSH key format
        valid_key_types = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
        if not any(ssh_key.startswith(key_type) for key_type in valid_key_types):
            print(f"Invalid SSH key format. Key starts with: {ssh_key.split()[0] if ' ' in ssh_key else ssh_key[:20]}")
            return jsonify({
                'status': 'error', 
                'message': 'Invalid SSH key format. Supported formats: RSA, Ed25519, ECDSA'
            })

        # Check for existing instances with proper ownership verification
        ec2_client = get_ec2_client_from_env()
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:UserID',
                    'Values': [str(user_data['id'])]
                },
                {
                    'Name': 'tag:DiscordID',
                    'Values': [str(discord_user)]
                },
                {
                    'Name': 'instance-state-name',
                    'Values': ['pending', 'running', 'stopping', 'stopped']
                }
            ]
        )
        
        # Check for any active or stopped instances that belong to this user
        active_instances = []
        stopped_instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Verify instance ownership via tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                if (tags.get('UserID') == str(user_data['id']) and 
                    tags.get('DiscordID') == str(discord_user)):
                    state = instance['State']['Name']
                    if state in ['running', 'pending']:
                        active_instances.append(instance)
                    elif state == 'stopped':
                        stopped_instances.append(instance)
        
        if active_instances:
            print(f"User has running instance: {active_instances[0]['InstanceId']}")
            return jsonify({'status': 'error', 'message': 'You already have a running instance. Please stop it first.'})
        
        # Create new instance with SSH key
        print("Creating new instance...")
        instance_info = create_instance_from_template(user_data['id'], discord_user, ssh_key)
        
        if instance_info:
            print(f"Instance created successfully: {instance_info['instance_id']}")
            success_message = (
                f"New instance created successfully!\n"
                f"Name: {instance_info['name']}\n"
                f"Instance ID: {instance_info['instance_id']}\n"
                f"Region: {instance_info['region']}\n"
                f"State: {instance_info['state']}\n"
                f"IP: {instance_info.get('public_ip', 'Not available yet')}\n\n"
                f"To connect: ssh ec2-user@{instance_info.get('public_ip', 'IP_ADDRESS')}"
            )
            return jsonify({
                'status': 'success',
                'message': success_message,
                'instance_id': instance_info.get('instance_id'),
                'name': instance_info.get('name'),
                'state': instance_info.get('state'),
                'region': instance_info.get('region'),
                'public_ip': instance_info.get('public_ip')
            })
        else:
            print("Instance creation failed with no specific error")
            return jsonify({'status': 'error', 'message': 'Failed to create instance. Check server logs for details.'})

    except Exception as e:
        error_msg = str(e)
        print(f"Error in api_start_instance: {error_msg}")
        return jsonify({'status': 'error', 'message': error_msg})

@app.route('/api/stop/<discord_user>', methods=['GET', 'POST'])
def api_stop_instance(discord_user):
    try:
        # Get Discord username from request
        discord_username = None
        if request.method == 'POST':
            data = request.get_json()
            discord_username = data.get('discord_username') if data else None
        
        user = get_or_create_discord_user(discord_user, discord_username)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'})

        # Get instances using env credentials
        ec2_client = get_ec2_client_from_env()
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:UserID',
                    'Values': [str(user['id'])]
                },
                {
                    'Name': 'tag:DiscordID',
                    'Values': [str(discord_user)]
                },
                {
                    'Name': 'instance-state-name',
                    'Values': ['running', 'pending']
                }
            ]
        )
        
        # Find running instances that belong to this user
        running_instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Verify instance ownership via tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                if (tags.get('UserID') == str(user['id']) and 
                    tags.get('DiscordID') == str(discord_user)):
                    running_instances.append(instance)
        
        if not running_instances:
            return jsonify({'status': 'error', 'message': 'No running instances found'})
        
        # Stop the first running instance found
        instance = running_instances[0]
        instance_id = instance['InstanceId']
        
        # Stop the instance
        ec2_client.stop_instances(InstanceIds=[instance_id])
        
        return jsonify({
            'status': 'success',
            'message': f'Instance {instance_id} is being stopped'
        })
        
    except Exception as e:
        error_msg = str(e)
        print(f"Error in api_stop_instance: {error_msg}")
        if 'AuthFailure' in error_msg:
            return jsonify({'status': 'error', 'message': 'AWS credentials are invalid. Please contact an administrator.'})
        return jsonify({'status': 'error', 'message': error_msg})

@app.route('/api/ip/<discord_user>')
def api_get_ip(discord_user):
    try:
        # Get Discord username from query parameter
        discord_username = request.args.get('username')
        user = get_or_create_discord_user(discord_user, discord_username)
        if not user:
            return jsonify({'status': 'error', 'message': 'Failed to get/create user'})

        # Get instances using env credentials
        ec2_client = get_ec2_client_from_env()
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:UserID',
                    'Values': [str(user['id'])]
                }
            ]
        )
        
        # First check for running or pending instances
        active_instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                state = instance['State']['Name']
                if state in ['running', 'pending']:
                    active_instances.append({
                        'instance_id': instance['InstanceId'],
                        'state': state,
                        'public_ip': instance.get('PublicIpAddress', 'N/A')
                    })
        
        if active_instances:
            instance = active_instances[0]
            return jsonify({
                'status': 'success',
                'ip': instance['public_ip'],
                'state': instance['state']
            })
            
        # If no running/pending instances, check for stopped ones
        stopped_instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'stopped':
                    stopped_instances.append({
                        'instance_id': instance['InstanceId'],
                        'state': 'stopped',
                        'public_ip': None
                    })
        
        if stopped_instances:
            instance = stopped_instances[0]
            return jsonify({
                'status': 'success',
                'ip': None,
                'state': 'stopped'
            })
            
        return jsonify({'status': 'error', 'message': 'No instance found. Use !start to create one.'})
    except Exception as e:
        print(f"Error in api_get_ip: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/delete/<discord_user>', methods=['POST'])
def api_delete_instance(discord_user):
    try:
        # Get user data
        user_data = get_discord_user(discord_user)
        if not user_data:
            return jsonify({'status': 'error', 'message': 'User not found'})

        # Get EC2 client
        ec2_client = get_ec2_client_from_env()
        
        # Check for existing instances
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:UserID',
                    'Values': [str(user_data['id'])]
                },
                {
                    'Name': 'tag:DiscordID',
                    'Values': [str(discord_user)]
                },
                {
                    'Name': 'instance-state-name',
                    'Values': ['stopped']
                }
            ]
        )
        
        # Find stopped instances that belong to this user
        stopped_instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Double check instance ownership via tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                if (tags.get('UserID') == str(user_data['id']) and 
                    tags.get('DiscordID') == str(discord_user)):
                    stopped_instances.append(instance)
        
        if not stopped_instances:
            return jsonify({'status': 'error', 'message': 'No stopped instances found to delete'})
        
        # Delete the first stopped instance found
        instance = stopped_instances[0]
        instance_id = instance['InstanceId']
        
        # Get instance tags for verification
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        
        # Final ownership verification
        if (tags.get('UserID') != str(user_data['id']) or 
            tags.get('DiscordID') != str(discord_user)):
            return jsonify({
                'status': 'error',
                'message': 'You do not have permission to delete this instance'
            })
        
        # Terminate the instance
        ec2_client.terminate_instances(InstanceIds=[instance_id])
        
        return jsonify({
            'status': 'success',
            'message': f'Instance {instance_id} has been scheduled for deletion'
        })
        
    except Exception as e:
        print(f"Error in api_delete_instance: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/admin/delete/<instance_id>', methods=['POST'])
def api_admin_delete_instance(instance_id):
    try:
        # Get the user making the request
        data = request.get_json()
        discord_id = data.get('discord_id')
        user_data = get_discord_user(discord_id)
        
        if not user_data or not user_data.get('is_admin', False):
            return jsonify({'status': 'error', 'message': 'Unauthorized. Admin access required.'})
        
        # Get EC2 client
        ec2_client = get_ec2_client_from_env()
        
        # Verify instance exists
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            if not response['Reservations']:
                return jsonify({'status': 'error', 'message': f'Instance {instance_id} not found'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Instance {instance_id} not found'})
        
        # Terminate the instance
        ec2_client.terminate_instances(InstanceIds=[instance_id])
        
        return jsonify({
            'status': 'success',
            'message': f'Instance {instance_id} has been scheduled for deletion'
        })
        
    except Exception as e:
        print(f"Error in api_admin_delete_instance: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

def get_or_create_discord_user(discord_user, discord_username=None):
    """Get or create a user for a Discord user"""
    # First try to find existing user
    for user_data in users.values():
        if user_data.get('discord_id') == discord_user:
            # Update username if provided
            if discord_username and user_data.get('discord_username') != discord_username:
                user_data['discord_username'] = discord_username
                save_users(users)
            return user_data
    
    # Create new user if not found
    new_id = max([user['id'] for user in users.values()], default=0) + 1
    username = f"discord_{discord_user}"
    password = secrets.token_urlsafe(16)
    
    users[username] = {
        'id': new_id,
        'username': username,
        'password_hash': generate_password_hash(password),
        'discord_id': discord_user,
        'discord_username': discord_username,
        'role': 'user',
        'instances': []
    }
    
    save_users(users)
    return users[username]

def get_discord_user(discord_user):
    """Get or create user by Discord ID"""
    # First try to find existing user
    for user_data in users.values():
        if user_data.get('discord_id') == str(discord_user):
            return user_data
    
    # Create new user if not found
    new_id = max([user['id'] for user in users.values()], default=0) + 1
    username = f"discord_{discord_user}"
    password = secrets.token_urlsafe(16)  # Generate random password
    
    users[username] = {
        'id': new_id,
        'username': username,
        'password_hash': generate_password_hash(password),
        'discord_id': str(discord_user),
        'role': 'user',
        'instances': []
    }
    
    save_users(users)
    return users[username]

def create_instance_from_template(user_id, discord_user, ssh_key=None):
    """Create an EC2 instance from template with user's SSH key"""
    try:
        print(f"Starting instance creation for user {user_id} (Discord: {discord_user})")
        ec2_client = get_ec2_client()
        
        # Get user data to get Discord username
        discord_username = None
        for user_data in users.values():
            if user_data.get('discord_id') == discord_user:
                discord_username = user_data.get('discord_username', '').split('#')[0]  # Get username without discriminator
                break
        
        # Create instance name using Discord username if available
        instance_name = f"discord-{discord_username or discord_user}"
        print(f"Creating instance with name: {instance_name}")
        
        # Get latest Amazon Linux 2023 AMI
        print("Searching for Amazon Linux 2023 AMI...")
        response = ec2_client.describe_images(
            Filters=[
                {'Name': 'name', 'Values': ['al2023-ami-2023.*-x86_64']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'owner-alias', 'Values': ['amazon']}
            ],
            Owners=['amazon']
        )
        
        if not response['Images']:
            print("No AMI found matching criteria")
            raise Exception("No suitable AMI found")
            
        # Sort by creation date to get the latest
        latest_ami = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
        print(f"Found AMI: {latest_ami['ImageId']} ({latest_ami['Name']})")
        
        # Create key pair name based on user and timestamp
        key_name = f"ec2-{discord_username or discord_user}-{int(time.time())}"
        print(f"Creating key pair: {key_name}")
        
        # Import the user's SSH key
        if ssh_key:
            try:
                print("Importing SSH key...")
                ec2_client.import_key_pair(
                    KeyName=key_name,
                    PublicKeyMaterial=ssh_key.encode()
                )
                print("SSH key imported successfully")
            except Exception as e:
                print(f"Error importing key pair: {str(e)}")
                raise Exception(f"Failed to import SSH key: {str(e)}")
        
        # Create security group with user-friendly name
        sg_name = f"ec2-{discord_username or discord_user}-{int(time.time())}"
        sg_desc = f"Security group for Discord user {discord_username or discord_user}"
        
        try:
            print("Creating security group...")
            vpc_response = ec2_client.describe_vpcs(
                Filters=[{'Name': 'isDefault', 'Values': ['true']}]
            )
            if not vpc_response['Vpcs']:
                raise Exception("No default VPC found")
                
            vpc_id = vpc_response['Vpcs'][0]['VpcId']
            print(f"Using VPC: {vpc_id}")
            
            sg_response = ec2_client.create_security_group(
                GroupName=sg_name,
                Description=sg_desc,
                VpcId=vpc_id
            )
            
            security_group_id = sg_response['GroupId']
            print(f"Created security group: {security_group_id}")
            
            # Allow SSH access
            print("Configuring security group rules...")
            ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
            print("Security group configured successfully")
        except Exception as e:
            print(f"Error creating security group: {str(e)}")
            raise Exception(f"Failed to create security group: {str(e)}")
        
        print(f"Creating new instance: {instance_name}")
        try:
            response = ec2_client.run_instances(
                ImageId=latest_ami['ImageId'],
                InstanceType='t2.micro',
                MinCount=1,
                MaxCount=1,
                KeyName=key_name,
                SecurityGroupIds=[security_group_id],
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': instance_name},
                            {'Key': 'UserID', 'Value': str(user_id)},
                            {'Key': 'DiscordID', 'Value': str(discord_user)},
                            {'Key': 'DiscordUsername', 'Value': discord_username or ''},
                            {'Key': 'ManagedBy', 'Value': 'Discord-Bot'}
                        ]
                    }
                ]
            )
            print("Instance creation initiated successfully")
        except Exception as e:
            print(f"Error in run_instances: {str(e)}")
            raise Exception(f"Failed to launch instance: {str(e)}")
        
        instance = response['Instances'][0]
        instance_id = instance['InstanceId']
        print(f"Instance ID: {instance_id}")
        
        # Wait for instance to be running
        print("Waiting for instance to be running...")
        waiter = ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        print("Instance is now running")
        
        # Get instance details with public IP
        instance_response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = instance_response['Reservations'][0]['Instances'][0]
        public_ip = instance.get('PublicIpAddress', 'Not available yet')
        
        return {
            'instance_id': instance_id,
            'name': instance_name,
            'state': instance['State']['Name'],
            'region': session.get('aws_region', 'us-east-1'),
            'public_ip': public_ip
        }
        
    except Exception as e:
        print(f"Error creating instance: {str(e)}")
        # Clean up resources on failure
        try:
            print("Cleaning up resources...")
            if 'key_name' in locals():
                print(f"Deleting key pair: {key_name}")
                ec2_client.delete_key_pair(KeyName=key_name)
            if 'security_group_id' in locals():
                print(f"Deleting security group: {security_group_id}")
                ec2_client.delete_security_group(GroupId=security_group_id)
            print("Cleanup completed")
        except Exception as cleanup_error:
            print(f"Error during cleanup: {str(cleanup_error)}")
        return None

def init_app():
    """Initialize the application with default data"""
    global users
    
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        # Create default admin user if no users exist
        users = {
            'admin': {
                'id': 1,
                'username': 'admin',
                'password_hash': generate_password_hash('admin'),  # Change this password after first login!
                'role': 'admin',
                'instances': []
            }
        }
        save_users(users)
    except Exception as e:
        print(f"Error loading users: {str(e)}")
        users = {}
    
    # Ensure at least one admin exists
    admin_exists = any(user.get('role') == 'admin' for user in users.values())
    if not admin_exists and users:
        # Convert first user to admin if no admin exists
        first_user = next(iter(users.values()))
        first_user['role'] = 'admin'
        save_users(users)
    
    # Start the SSH session monitoring thread
    ssh_monitor_thread = threading.Thread(target=check_ssh_sessions, daemon=True)
    ssh_monitor_thread.start()
    
    # Start the inactive instances check thread
    inactive_check_thread = threading.Thread(target=check_inactive_instances, daemon=True)
    inactive_check_thread.start()

if __name__ == '__main__':
    init_app()
    app.run(host='0.0.0.0', port=5000, debug=True) 