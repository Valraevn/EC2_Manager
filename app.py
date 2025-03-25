from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import boto3
import os
from dotenv import load_dotenv
import psutil
import threading
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# AWS Configuration
aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_region = os.getenv('AWS_REGION')

# In-memory storage
users = {
    'test_user': {
        'id': 1,
        'username': 'test_user',
        'password': 'test_password',  # In production, use proper password hashing
        'instances': []
    }
}

instances = {
    'i-0123456789abcdef0': {
        'id': 1,
        'instance_id': 'i-0123456789abcdef0',
        'name': 'Test Instance',
        'public_ip': None,
        'state': 'stopped',
        'last_activity': datetime.utcnow(),
        'user_id': 1
    }
}

# Models
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.password = user_data['password']
        self.instances = user_data['instances']

    @staticmethod
    def get(user_id):
        for user_data in users.values():
            if user_data['id'] == user_id:
                return User(user_data)
        return None

class Instance:
    def __init__(self, instance_data):
        self.id = instance_data['id']
        self.instance_id = instance_data['instance_id']
        self.name = instance_data['name']
        self.public_ip = instance_data['public_ip']
        self.state = instance_data['state']
        self.last_activity = instance_data['last_activity']
        self.user_id = instance_data['user_id']

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

def get_ec2_client():
    return boto3.client('ec2',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )

def check_ssh_sessions():
    while True:
        for instance_data in instances.values():
            if instance_data['state'] == 'running':
                try:
                    ec2 = get_ec2_client()
                    response = ec2.describe_instances(InstanceIds=[instance_data['instance_id']])
                    if response['Reservations']:
                        instance_data['state'] = response['Reservations'][0]['Instances'][0]['State']['Name']
                        instance_data['public_ip'] = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
                except Exception as e:
                    print(f"Error checking instance {instance_data['instance_id']}: {str(e)}")
        time.sleep(300)  # Check every 5 minutes

# Routes
@app.route('/')
@login_required
def index():
    user_instances = [Instance(instance) for instance in instances.values() 
                     if instance['user_id'] == current_user.id]
    return render_template('index.html', instances=user_instances)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = users.get(username)
        if user_data and user_data['password'] == password:  # In production, use proper password hashing
            login_user(User(user_data))
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/instance/<instance_id>/start')
@login_required
def start_instance(instance_id):
    instance_data = instances.get(instance_id)
    if not instance_data or instance_data['user_id'] != current_user.id:
        return jsonify({'status': 'error', 'message': 'Instance not found'})
    
    try:
        ec2 = get_ec2_client()
        ec2.start_instances(InstanceIds=[instance_id])
        instance_data['state'] = 'starting'
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/instance/<instance_id>/stop')
@login_required
def stop_instance(instance_id):
    instance_data = instances.get(instance_id)
    if not instance_data or instance_data['user_id'] != current_user.id:
        return jsonify({'status': 'error', 'message': 'Instance not found'})
    
    try:
        ec2 = get_ec2_client()
        ec2.stop_instances(InstanceIds=[instance_id])
        instance_data['state'] = 'stopping'
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/instance/<instance_id>/status')
@login_required
def instance_status(instance_id):
    instance_data = instances.get(instance_id)
    if not instance_data or instance_data['user_id'] != current_user.id:
        return jsonify({'status': 'error', 'message': 'Instance not found'})
    
    try:
        ec2 = get_ec2_client()
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if response['Reservations']:
            instance_data['state'] = response['Reservations'][0]['Instances'][0]['State']['Name']
            instance_data['public_ip'] = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
            return jsonify({
                'state': instance_data['state'],
                'public_ip': instance_data['public_ip']
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def init_app():
    # Start the SSH session monitoring thread
    ssh_monitor_thread = threading.Thread(target=check_ssh_sessions, daemon=True)
    ssh_monitor_thread.start()

if __name__ == '__main__':
    init_app()
    app.run(host='0.0.0.0', port=5000, debug=True) 