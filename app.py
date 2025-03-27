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

def get_instances_for_user(user_id):
    """Get EC2 instances for a specific user"""
    try:
        ec2_client = get_ec2_client()
        response = ec2_client.describe_instances()
        
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Get instance tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                
                # Only include instances that belong to this user
                if tags.get('UserID') == str(user_id):
                    # Format the timestamp to be more readable
                    launch_time = instance.get('LaunchTime', '')
                    if launch_time:
                        launch_time = launch_time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Get public IP from current state or tags
                    public_ip = instance.get('PublicIpAddress')
                    if not public_ip and instance['State']['Name'] == 'stopped':
                        public_ip = tags.get('LastKnownIP')
                    
                    instances.append({
                        'instance_id': instance['InstanceId'],
                        'name': tags.get('Name', 'Unnamed'),
                        'state': instance['State']['Name'],
                        'public_ip': instance.get('PublicIpAddress') or tags.get('LastKnownIP'),
                        'region': session.get('aws_region', 'us-east-1'),
                        'last_activity': launch_time
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

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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

def check_ssh_sessions():
    while True:
        try:
            # Get all instances for all users
            aws_region = session.get('aws_region', os.getenv('AWS_REGION'))
            if aws_region == 'global':
                regions = get_all_regions()
                for region in regions:
                    ec2 = get_ec2_client(region)
                    response = ec2.describe_instances()
                    # Process instances...
            else:
                ec2 = get_ec2_client()
                response = ec2.describe_instances()
                # Process instances...
        except Exception as e:
            print(f"Error in SSH session check: {str(e)}")
        time.sleep(300)  # Check every 5 minutes

def check_inactive_instances():
    """Check for and stop instances that have been inactive for 60 minutes"""
    while True:
        try:
            # Get all instances for all users
            aws_region = session.get('aws_region', os.getenv('AWS_REGION'))
            if aws_region == 'global':
                regions = get_all_regions()
                for region in regions:
                    ec2 = get_ec2_client(region)
                    response = ec2.describe_instances()
                    process_inactive_instances(response, region)
            else:
                ec2 = get_ec2_client()
                response = ec2.describe_instances()
                process_inactive_instances(response, aws_region)
        except Exception as e:
            print(f"Error checking inactive instances: {str(e)}")
        time.sleep(300)  # Check every 5 minutes

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
    
    # Get instances for the current user
    user_instances = get_instances_for_user(current_user.id)
    return render_template('index.html', instances=user_instances)

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
        'instances': []
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
        
        # Clear any existing session data first
        session.pop('aws_access_key', None)
        session.pop('aws_secret_key', None)
        session.pop('aws_region', None)
        
        # Save to session with permanent flag
        session.permanent = True
        session['aws_access_key'] = aws_access_key
        session['aws_secret_key'] = aws_secret_key
        session['aws_region'] = aws_region
        
        # Also set environment variables as backup
        os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_key
        os.environ['AWS_REGION'] = aws_region if aws_region != 'global' else 'us-east-1'
        
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

def init_app():
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    # Create default user if no users exist
    if not users:
        users['admin'] = {
            'id': 1,
            'username': 'admin',
            'password_hash': generate_password_hash('admin'),
            'instances': []
        }
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