import discord
from discord.ext import commands
import requests
import os
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()

# Bot configuration
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
ALLOWED_CHANNEL_ID = int(os.getenv('ALLOWED_CHANNEL_ID', 0))
API_BASE_URL = os.getenv('API_BASE_URL', 'http://localhost:5000')

# Message deduplication
processed_messages = {}
MESSAGE_TIMEOUT = 5  # seconds

def deduplicate_message(message_id):
    current_time = time.time()
    if message_id in processed_messages:
        if current_time - processed_messages[message_id] < MESSAGE_TIMEOUT:
            return False
    processed_messages[message_id] = current_time
    return True

# Clean up old messages periodically
def cleanup_old_messages():
    current_time = time.time()
    global processed_messages
    processed_messages = {msg_id: timestamp for msg_id, timestamp in processed_messages.items() 
                         if current_time - timestamp < MESSAGE_TIMEOUT}

print("Starting bot with configuration:")
print(f"ALLOWED_CHANNEL_ID: {ALLOWED_CHANNEL_ID}")
print(f"API_BASE_URL: {API_BASE_URL}")
print(f"DISCORD_TOKEN length: {len(DISCORD_TOKEN) if DISCORD_TOKEN else 0}")

# Set up bot with required intents
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

@bot.event
async def on_ready():
    print(f'Bot is ready! Logged in as {bot.user.name} (ID: {bot.user.id})')
    print(f'Connected to {len(bot.guilds)} guilds:')
    for guild in bot.guilds:
        print(f'- {guild.name} (ID: {guild.id})')
        channel = discord.utils.get(guild.channels, id=ALLOWED_CHANNEL_ID)
        if channel:
            print(f'Found allowed channel: {channel.name}')
        else:
            print(f'Could not find channel with ID: {ALLOWED_CHANNEL_ID}')

@bot.event
async def on_guild_join(guild):
    print(f'Bot joined new guild: {guild.name} (ID: {guild.id})')

@bot.event
async def on_error(event, *args, **kwargs):
    print(f'Error in {event}:')
    import traceback
    traceback.print_exc()

@bot.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == bot.user:
        return

    # Clean up old messages periodically
    cleanup_old_messages()

    # Check if this is a command message
    if message.content.startswith('!'):
        # Deduplicate the message
        if not deduplicate_message(message.id):
            return

    # Process the command
    await bot.process_commands(message)

def is_allowed_channel():
    async def predicate(ctx):
        if ctx.channel.id != ALLOWED_CHANNEL_ID:
            await ctx.send("This command can only be used in the designated channel.")
            return False
        return True
    return commands.check(predicate)

@bot.command(name='start')
@is_allowed_channel()
async def start_instance(ctx, *, ssh_key=None):
    """Start your EC2 instance"""
    try:
        if not ssh_key:
            await ctx.send("❌ Error: Please provide your SSH public key. Usage: `!start your_ssh_public_key_here`")
            return
            
        response = requests.post(
            f'{API_BASE_URL}/api/start/{ctx.author.id}',
            json={
                'ssh_key': ssh_key,
                'discord_username': f"{ctx.author.name}#{ctx.author.discriminator}" if ctx.author.discriminator != '0' else ctx.author.name
            }
        )
        data = response.json()
        
        if data['status'] == 'success':
            # Send the formatted message from the API
            await ctx.send(f"✅ {data['message']}")
        else:
            await ctx.send(f"❌ Error: {data['message']}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='stop')
@is_allowed_channel()
async def stop_instance(ctx):
    """Stop your EC2 instance"""
    try:
        response = requests.post(
            f'{API_BASE_URL}/api/stop/{ctx.author.id}',
            json={
                'discord_username': f"{ctx.author.name}#{ctx.author.discriminator}" if ctx.author.discriminator != '0' else ctx.author.name
            }
        )
        data = response.json()
        
        if data['status'] == 'success':
            await ctx.send(f"✅ {data['message']}")
        else:
            await ctx.send(f"❌ Error: {data['message']}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='ip')
@is_allowed_channel()
async def get_ip(ctx):
    """Get your EC2 instance IP address"""
    try:
        response = requests.get(
            f'{API_BASE_URL}/api/ip/{ctx.author.id}?username={ctx.author.name}#{ctx.author.discriminator if ctx.author.discriminator != "0" else ""}'
        )
        data = response.json()
        
        if data['status'] == 'success':
            status_emoji = "🟢" if data['state'] == 'running' else "🔴"
            ip_display = data['ip'] if data['ip'] else 'N/A'
            await ctx.send(f"{status_emoji} Your instance IP: {ip_display} (State: {data['state']})")
        else:
            await ctx.send(f"❌ Error: {data['message']}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='delete')
@is_allowed_channel()
async def delete_instance(ctx):
    """Delete your stopped EC2 instance"""
    try:
        response = requests.post(
            f'{API_BASE_URL}/api/delete/{ctx.author.id}',
            json={
                'discord_username': f"{ctx.author.name}#{ctx.author.discriminator}" if ctx.author.discriminator != '0' else ctx.author.name
            }
        )
        data = response.json()
        
        if data['status'] == 'success':
            await ctx.send(f"✅ {data['message']}")
        else:
            await ctx.send(f"❌ Error: {data['message']}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='admin-delete')
@is_allowed_channel()
async def admin_delete_instance(ctx, instance_id=None):
    """Admin command to delete any EC2 instance"""
    try:
        if not instance_id:
            await ctx.send("❌ Error: Please provide an instance ID. Usage: `!admin-delete instance_id`")
            return

        response = requests.post(
            f'{API_BASE_URL}/api/admin/delete/{instance_id}',
            json={
                'discord_username': f"{ctx.author.name}#{ctx.author.discriminator}" if ctx.author.discriminator != '0' else ctx.author.name,
                'discord_id': str(ctx.author.id)
            }
        )
        data = response.json()
        
        if data['status'] == 'success':
            await ctx.send(f"✅ {data['message']}")
        else:
            await ctx.send(f"❌ Error: {data['message']}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='help')
@is_allowed_channel()
async def help_command(ctx):
    """Show available commands"""
    help_text = """
**Available Commands:**
`!start <ssh_public_key>` - Start your EC2 instance (restarts existing stopped instance if you have one)
`!stop` - Stop your running instance (preserves data and configuration)
`!delete` - Delete your stopped instance (only use if you want to start fresh)
`!ip` - Get your instance's IP address and state

**Instance Management:**
• You can have one instance at a time
• Stopping an instance preserves its data and configuration
• Use `!start` to restart a stopped instance
• Use `!delete` only if you want to create a fresh instance

**Supported SSH Key Types:**
• RSA (starts with 'ssh-rsa')
• Ed25519 (starts with 'ssh-ed25519')
• ECDSA (starts with 'ecdsa-sha2-nistp256/384/521')

Example:
`!start ssh-rsa AAAAB3NzaC1... user@host`
or
`!start ssh-ed25519 AAAAC3... user@host`
    """
    await ctx.send(help_text)

if __name__ == '__main__':
    if not DISCORD_TOKEN:
        print("Error: DISCORD_TOKEN not found in environment variables")
    elif not ALLOWED_CHANNEL_ID:
        print("Error: ALLOWED_CHANNEL_ID not found in environment variables")
    else:
        print("Starting bot...")
        bot.run(DISCORD_TOKEN, log_handler=None) 