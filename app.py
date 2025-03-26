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
    # First try to get from session
    aws_access_key = session.get('aws_access_key')
    aws_secret_key = session.get('aws_secret_key')
    aws_region = session.get('aws_region')
    
    # If not in session, try environment variables
    if not aws_access_key:
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
    if not aws_secret_key:
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    if not aws_region:
        aws_region = os.getenv('AWS_REGION')
    
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
    user_instances = []
    aws_region = session.get('aws_region', os.getenv('AWS_REGION'))
    
    try:
        if aws_region == 'global':
            regions = get_all_regions()
            for region in regions:
                ec2 = get_ec2_client(region)
                response = ec2.describe_instances()
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        name = 'Unnamed'
                        if 'Tags' in instance:
                            name_tag = next((tag for tag in instance['Tags'] if tag['Key'] == 'Name'), None)
                            if name_tag:
                                name = name_tag['Value']
                        
                        user_instances.append({
                            'id': instance['InstanceId'],
                            'instance_id': instance['InstanceId'],
                            'name': name,
                            'public_ip': instance.get('PublicIpAddress', 'N/A'),
                            'state': instance['State']['Name'],
                            'last_activity': datetime.utcnow().isoformat(),
                            'user_id': user_id,
                            'region': region
                        })
        else:
            ec2 = get_ec2_client()
            response = ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    name = 'Unnamed'
                    if 'Tags' in instance:
                        name_tag = next((tag for tag in instance['Tags'] if tag['Key'] == 'Name'), None)
                        if name_tag:
                            name = name_tag['Value']
                    
                    user_instances.append({
                        'id': instance['InstanceId'],
                        'instance_id': instance['InstanceId'],
                        'name': name,
                        'public_ip': instance.get('PublicIpAddress', 'N/A'),
                        'state': instance['State']['Name'],
                        'last_activity': datetime.utcnow().isoformat(),
                        'user_id': user_id,
                        'region': aws_region
                    })
    except Exception as e:
        print(f"Error fetching instances: {str(e)}")
        flash(f"Error fetching instances: {str(e)}", 'error')
    
    return user_instances

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
                        # Check if instance belongs to user
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                if tag['Key'] == 'UserID' and tag['Value'] == str(user_id):
                                    return instance, region
                except:
                    continue
        else:
            # Try specific region
            ec2 = get_ec2_client()
            response = ec2.describe_instances(InstanceIds=[instance_id])
            if response['Reservations']:
                instance = response['Reservations'][0]['Instances'][0]
                # Check if instance belongs to user
                if 'Tags' in instance:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'UserID' and tag['Value'] == str(user_id):
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
        self.launch_time = instance_data.get('LaunchTime')

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
    aws_access_key, aws_secret_key, aws_region = get_aws_credentials()
    return render_template('settings.html',
                         aws_access_key=aws_access_key,
                         aws_secret_key=aws_secret_key,
                         aws_region=aws_region)

@app.route('/settings', methods=['POST'])
@login_required
def save_settings():
    aws_access_key = request.form.get('aws_access_key')
    aws_secret_key = request.form.get('aws_secret_key')
    aws_region = request.form.get('aws_region')
    
    if not all([aws_access_key, aws_secret_key, aws_region]):
        flash('All fields are required', 'danger')
        return redirect(url_for('settings'))
    
    try:
        # Test the credentials
        boto3.client('ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        ).describe_regions()
        
        # Save to session
        session['aws_access_key'] = aws_access_key
        session['aws_secret_key'] = aws_secret_key
        session['aws_region'] = aws_region
        
        flash('AWS credentials saved successfully', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Invalid AWS credentials: {str(e)}', 'danger')
        return redirect(url_for('settings'))

@app.route('/instance/<instance_id>/start')
@login_required
def start_instance(instance_id):
    instance, region = get_instance_by_id(instance_id, current_user.id)
    if not instance:
        return jsonify({'status': 'error', 'message': 'Instance not found'})
    
    try:
        ec2 = get_ec2_client(region)
        ec2.start_instances(InstanceIds=[instance_id])
        return jsonify({'status': 'success'})
    except Exception as e:
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

if __name__ == '__main__':
    init_app()
    app.run(host='0.0.0.0', port=5000, debug=True) 