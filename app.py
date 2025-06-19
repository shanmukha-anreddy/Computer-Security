import os
import csv
import uuid
from datetime import datetime
import functools

from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from ecc_crypto import (
    generate_ecc_keys, save_private_key, save_public_key, 
    load_private_key, load_public_key, encrypt_data, decrypt_data, 
    serialize_public_key_to_pem, serialize_private_key_to_pem,
    load_public_key_from_pem, load_private_key_from_pem
)
from lsb_stego import hide_data_in_image, extract_data_from_image
from blockchain_ipfs import upload_to_pinata # Assuming upload_to_pinata is preferred

# Initialize Flask App
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_supersecretkey_replace_in_prod') # IMPORTANT: Set a strong secret key

# Configuration
UPLOAD_FOLDER = 'uploads'
RESULTS_FOLDER = 'results' # May not be needed as much if not saving keys server-side
USER_DATA_FILE = 'users.csv'
MESSAGE_DATA_FILE = 'messages.csv'
TRANSACTION_DATA_FILE = 'transactions.csv'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True) # For temporary stego images if needed

# File upload settings
ALLOWED_EXTENSIONS = {'png'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# --- CSV Helper Functions ---
def get_user(username):
    try:
        with open(USER_DATA_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['username'] == username:
                    return row
    except FileNotFoundError:
        pass # Handled by initial setup or error if critical
    return None

def add_user(username, password_hash, public_key_pem, balance):
    with open(USER_DATA_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([username, password_hash, public_key_pem, balance])

def get_user_public_key(username):
    user = get_user(username)
    return user['public_key_pem'] if user else None

def update_balance(username, new_balance):
    rows = []
    updated = False
    # Ensure fieldnames match users.csv structure including the balance column
    fieldnames = ['username', 'password_hash', 'public_key_pem', 'balance']
    
    try:
        with open(USER_DATA_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            # It's crucial that USER_DATA_FILE has headers. Our startup logic handles this.
            # If reader.fieldnames is different from expected, there might be an issue.
            # For simplicity, we assume fieldnames from DictReader are correct if file has headers.
            # If we need to be defensive, we could use reader.fieldnames if available and compatible.
            actual_fieldnames = reader.fieldnames if reader.fieldnames else fieldnames

            for row in reader:
                if row['username'] == username:
                    row['balance'] = str(new_balance) # Store balance as string
                    updated = True
                rows.append(row)
        
        if updated:
            with open(USER_DATA_FILE, 'w', newline='') as f:
                # Use the actual fieldnames read from the file if possible, 
                # or the predefined ones if the file was empty and DictReader didn't get them.
                writer = csv.DictWriter(f, fieldnames=actual_fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            return True # Successfully updated
        else:
            # User not found, or no update was made for other reasons.
            return False # Indicate user not found or no update occurred

    except FileNotFoundError:
        # This case should ideally be handled by app initialization logic ensuring USER_DATA_FILE exists.
        # print(f"Error: {USER_DATA_FILE} not found during balance update.") # Optional: log this
        return False # Indicate failure due to missing file
    except Exception as e:
        # print(f"An error occurred during balance update for {username}: {e}") # Optional: log this
        return False # Indicate general failure

def record_transaction(sender_username, recipient_username, amount, description="Unit Transfer"):
    transaction_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Fieldnames for transactions.csv: 
    # transaction_id,sender_username,recipient_username,amount,timestamp,description
    try:
        # Ensure TRANSACTION_DATA_FILE exists and has headers (handled by startup logic)
        with open(TRANSACTION_DATA_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([transaction_id, sender_username, recipient_username, str(amount), timestamp, description])
        return transaction_id # Return the ID of the recorded transaction, or True for success
    except Exception as e:
        # print(f"Error recording transaction: {e}") # Optional: log this
        return None # Indicate failure

def get_user_transactions(username):
    user_transactions = []
    try:
        with open(TRANSACTION_DATA_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            # Ensure TRANSACTION_DATA_FILE has headers, handled by startup logic.
            for row in reader:
                if row['sender_username'] == username or row['recipient_username'] == username:
                    # Optionally, add a 'type' field (sent/received) for easier display in template
                    if row['sender_username'] == username:
                        row['type'] = 'Sent'
                        row['counterparty'] = row['recipient_username']
                    else:
                        row['type'] = 'Received'
                        row['counterparty'] = row['sender_username']
                    user_transactions.append(row)
    except FileNotFoundError:
        # If the transactions file doesn't exist yet (e.g., no transactions made)
        pass # Return an empty list, which is appropriate
    except Exception as e:
        # print(f"Error reading transactions for {username}: {e}") # Optional: log this
        pass # Return an empty list or handle error as appropriate, empty list is safe default
    
    # Sort transactions by timestamp, most recent first
    return sorted(user_transactions, key=lambda x: x['timestamp'], reverse=True)


def record_message(sender, recipient, ipfs_hash):
    message_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(MESSAGE_DATA_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([message_id, sender, recipient, ipfs_hash, timestamp, 'False']) # False for is_read

def get_received_messages(username):
    messages = []
    try:
        with open(MESSAGE_DATA_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['recipient_username'] == username:
                    messages.append(row)
    except FileNotFoundError:
        pass # Or handle as error if file must exist
    return sorted(messages, key=lambda x: x['timestamp'], reverse=True)

def get_message_by_id(message_id):
    try:
        with open(MESSAGE_DATA_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['message_id'] == message_id:
                    return row
    except FileNotFoundError:
        pass
    return None

def mark_message_as_read(message_id):
    rows = []
    updated = False
    try:
        with open(MESSAGE_DATA_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            for row in reader:
                if row['message_id'] == message_id:
                    row['is_read'] = 'True'
                    updated = True
                rows.append(row)
        
        if updated:
            with open(MESSAGE_DATA_FILE, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
    except FileNotFoundError:
        pass # Should not happen if message was found

# --- Auth Decorator ---
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('username') is None:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- File Handling ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---
@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('signup'))
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))
        if get_user(username):
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)
        priv_key, pub_key = generate_ecc_keys()
        public_key_pem = serialize_public_key_to_pem(pub_key)
        private_key_pem_for_user = serialize_private_key_to_pem(priv_key)
        
        initial_balance = 100
        add_user(username, password_hash, public_key_pem, initial_balance)
        
        # Provide the private key to the user ONCE upon signup
        flash(f'Signup successful! Welcome, {username}!', 'success')
        flash('IMPORTANT: Save your private key below. It will not be shown again and is required to decrypt messages.', 'warning')
        return render_template('signup_success.html', username=username, private_key_pem=private_key_pem_for_user)
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            flash(f'Logged in successfully as {username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('welcome'))

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    current_user_username = session.get('username')
    user_details = get_user(current_user_username)
    current_balance = user_details.get('balance', '0') if user_details else '0'

    ipfs_hash_sent = None
    stego_image_sent_filename = None
    recipient_username_sent = None

    if request.method == 'POST':
        recipient_username = request.form.get('recipient_username')
        message_text = request.form.get('message')
        cover_image_file = request.files.get('cover_image')

        if not recipient_username or not message_text or not cover_image_file:
            flash('Recipient, message, and cover image are required!', 'danger')
            return redirect(url_for('home'))
        if not allowed_file(cover_image_file.filename):
            flash('Only PNG files are allowed for cover image!', 'danger')
            return redirect(url_for('home'))
        
        recipient = get_user(recipient_username)
        if not recipient:
            flash(f'Recipient username "{recipient_username}" not found.', 'danger')
            return redirect(url_for('home'))

        recipient_public_key_pem = recipient['public_key_pem']
        try:
            recipient_public_key = load_public_key_from_pem(recipient_public_key_pem.encode('utf-8'))
        except Exception as e:
            flash(f'Error loading recipient public key: {str(e)}. Contact admin.', 'danger')
            return redirect(url_for('home'))

        # Securely save uploaded cover image temporarily
        cover_filename = secure_filename(cover_image_file.filename)
        # Add unique prefix to avoid overwrites if multiple users upload 'cover.png'
        unique_cover_filename = f"{uuid.uuid4().hex}_{cover_filename}"
        cover_path = os.path.join(UPLOAD_FOLDER, unique_cover_filename)
        cover_image_file.save(cover_path)

        try:
            # 1. Encrypt data using recipient's public key
            encrypted_data_payload = encrypt_data(recipient_public_key, message_text.encode('utf-8'))
            
            # 2. Hide encrypted data in image
            # Add unique prefix to stego image as well
            stego_image_basename = f"stego_{uuid.uuid4().hex}.png"
            stego_output_path = os.path.join(UPLOAD_FOLDER, stego_image_basename) 
            hide_data_in_image(cover_path, encrypted_data_payload, output_path=stego_output_path)
            
            # 3. Upload stego image to IPFS
            ipfs_hash = upload_to_pinata(stego_output_path)
            
            # 4. Record message in CSV
            record_message(current_user_username, recipient_username, ipfs_hash)
            
            flash(f'Message sent successfully to {recipient_username}! IPFS Hash: {ipfs_hash}', 'success')
            ipfs_hash_sent = ipfs_hash
            stego_image_sent_filename = stego_image_basename # for optional download
            recipient_username_sent = recipient_username

        except Exception as e:
            # import traceback
            # traceback.print_exc()
            flash(f'An error occurred during sending: {str(e)}', 'danger')
        finally:
            # Clean up the temporary original cover image
            if os.path.exists(cover_path):
                os.remove(cover_path)
            # Optionally, clean up local stego image if only IPFS is primary, or keep it for download
            # For now, we make it downloadable, so it will be cleaned up by download_file or another mechanism

        # Retrieve all users for the dropdown, excluding the current user
    all_users = []
    try:
        with open(USER_DATA_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['username'] != current_user_username:
                    all_users.append(row['username'])
    except FileNotFoundError:
        flash('Error: User data file not found. Cannot populate recipient list.', 'danger')
    
    received_messages = get_received_messages(current_user_username)
    return render_template('home.html', 
                               username=current_user_username, 
                               received_messages=received_messages, 
                               users=all_users, 
                               ipfs_hash_sent=ipfs_hash_sent, 
                               stego_image_sent_filename=stego_image_sent_filename, 
                               recipient_username_sent=recipient_username_sent,
                               current_balance=current_balance)

@app.route('/send_units', methods=['POST'])
@login_required
def send_units():
    sender_username = session.get('username')
    recipient_username = request.form.get('recipient_username')
    amount_str = request.form.get('amount')

    # 1. Validate inputs
    if not recipient_username or not amount_str:
        flash('Recipient username and amount are required.', 'danger')
        return redirect(url_for('home'))

    try:
        amount = int(amount_str)
        if amount <= 0:
            flash('Amount must be a positive number.', 'danger')
            return redirect(url_for('home'))
    except ValueError:
        flash('Invalid amount format.', 'danger')
        return redirect(url_for('home'))

    if sender_username == recipient_username:
        flash('You cannot send Units to yourself.', 'danger')
        return redirect(url_for('home'))

    # 2. Check recipient existence
    recipient_user = get_user(recipient_username)
    if not recipient_user:
        flash(f'Recipient user "{recipient_username}" not found.', 'danger')
        return redirect(url_for('home'))

    # 3. Check sender's balance
    sender_user = get_user(sender_username)
    if not sender_user: # Should not happen for a logged-in user
        flash('Error fetching your user details. Please try again.', 'danger')
        return redirect(url_for('home'))
    
    try:
        sender_balance = int(sender_user.get('balance', 0))
    except ValueError:
        flash('Error reading your balance. Please contact support.', 'danger') # Should be int
        return redirect(url_for('home'))

    if sender_balance < amount:
        flash('Insufficient balance to complete the transaction.', 'danger')
        return redirect(url_for('home'))

    # 4. Perform the transaction
    try:
        recipient_balance = int(recipient_user.get('balance', 0))
    except ValueError:
        flash(f'Error reading recipient\'s balance. Transaction aborted.', 'danger') # Should be int
        return redirect(url_for('home'))

    new_sender_balance = sender_balance - amount
    new_recipient_balance = recipient_balance + amount

    # Update balances - this part needs to be atomic or have robust rollback
    sender_update_success = update_balance(sender_username, new_sender_balance)
    if not sender_update_success:
        flash('Failed to update your balance. Transaction aborted.', 'danger')
        return redirect(url_for('home'))

    recipient_update_success = update_balance(recipient_username, new_recipient_balance)
    if not recipient_update_success:
        flash(f'Failed to update recipient\'s balance. Transaction partially failed.', 'danger')
        # Attempt to roll back sender's balance
        revert_sender_success = update_balance(sender_username, sender_balance) # Revert to original
        if not revert_sender_success:
            flash('CRITICAL ERROR: Failed to roll back sender balance. Data inconsistency. Contact support!', 'danger')
        else:
            flash('Sender balance successfully rolled back after recipient update failure.', 'info')
        return redirect(url_for('home'))
        
    # 5. Record the transaction
    transaction_description = f"Transfer of {amount} Units from {sender_username} to {recipient_username}"
    transaction_id = record_transaction(sender_username, recipient_username, amount, transaction_description)
    
    if transaction_id:
        flash(f'{amount} Units successfully sent to {recipient_username}. Transaction ID: {transaction_id}', 'success')
    else:
        # This is a problematic state: balances are updated but transaction not recorded.
        flash('Balances updated, but failed to record transaction. Please contact support with details.', 'warning')

    return redirect(url_for('home'))

@app.route('/transactions')
@login_required
def transactions():
    current_user_username = session.get('username')
    user_txs = get_user_transactions(current_user_username)
    # Pass current_balance as well, as the navbar might be on this page too
    user_details = get_user(current_user_username)
    current_balance = user_details.get('balance', '0') if user_details else '0'
    return render_template('transactions.html', 
                           transactions=user_txs, 
                           username=current_user_username, 
                           current_balance=current_balance)

@app.route('/message/<message_id>')
@login_required
def view_message(message_id):
    message_details = get_message_by_id(message_id)
    if not message_details or message_details['recipient_username'] != session.get('username'):
        flash('Message not found or you do not have permission to view it.', 'danger')
        return redirect(url_for('home'))
    
    if message_details['is_read'] == 'False':
        mark_message_as_read(message_id)
        
    # For decryption, user needs to go to /extract. Here we just show details.
    return render_template('view_message.html', message=message_details)

@app.route('/extract', methods=['GET', 'POST'])
@login_required
def extract():
    decrypted_message_text = None
    if request.method == 'POST':
        ipfs_hash = request.form.get('ipfs_hash', '').strip()
        stego_image_file = request.files.get('stego_image')
        private_key_pem_str = request.form.get('private_key', '').strip()
        
        stego_path_to_process = None

        if not private_key_pem_str:
            flash('Your private key is required for decryption!', 'danger')
            return redirect(url_for('extract'))

        try:
            user_private_key = load_private_key_from_pem(private_key_pem_str.encode('utf-8'))
        except Exception as e:
            flash(f'Invalid private key format or key is corrupted: {str(e)}', 'danger')
            return redirect(url_for('extract'))

        temp_stego_image_path = None # To ensure cleanup
        try:
            if ipfs_hash:
                import requests # Consider moving to top if always used
                # Use a public gateway or your own
                # Ensure proper error handling for network issues/invalid hashes
                gateway_url = f"https://gateway.pinata.cloud/ipfs/{ipfs_hash}" # Or other public gateway
                response = requests.get(gateway_url, timeout=30)
                response.raise_for_status() # Raise an exception for HTTP errors
                
                temp_stego_filename = f"temp_stego_{uuid.uuid4().hex}.png"
                temp_stego_image_path = os.path.join(UPLOAD_FOLDER, temp_stego_filename)
                with open(temp_stego_image_path, 'wb') as f:
                    f.write(response.content)
                stego_path_to_process = temp_stego_image_path
            
            elif stego_image_file:
                if not allowed_file(stego_image_file.filename):
                    flash('Only PNG files are allowed for stego image!', 'danger')
                    return redirect(url_for('extract'))
                
                uploaded_stego_filename = secure_filename(stego_image_file.filename)
                temp_stego_filename = f"temp_upload_stego_{uuid.uuid4().hex}_{uploaded_stego_filename}"
                temp_stego_image_path = os.path.join(UPLOAD_FOLDER, temp_stego_filename)
                stego_image_file.save(temp_stego_image_path)
                stego_path_to_process = temp_stego_image_path
            else:
                flash('Please provide an IPFS hash or upload a stego image.', 'warning')
                return redirect(url_for('extract'))

            if not stego_path_to_process or not os.path.exists(stego_path_to_process):
                 flash('Stego image could not be processed.', 'danger')
                 return redirect(url_for('extract'))

            encrypted_payload_from_image = extract_data_from_image(stego_path_to_process)
            if not encrypted_payload_from_image:
                flash('No hidden data found in the image or data is corrupt.', 'danger')
                return redirect(url_for('extract'))

            decrypted_bytes = decrypt_data(user_private_key, encrypted_payload_from_image)
            decrypted_message_text = decrypted_bytes.decode('utf-8')
            flash('Message decrypted successfully!', 'success')

        except requests.exceptions.RequestException as e:
            flash(f'Failed to fetch image from IPFS: {str(e)}', 'danger')
        except Exception as e:
            # import traceback
            # tb = traceback.format_exc()
            # print(tb) # For server-side debugging
            flash(f'Decryption failed: {str(e)}. Ensure the stego image and private key are correct.', 'danger')
        finally:
            # Clean up temporary stego image from IPFS download or direct upload
            if temp_stego_image_path and os.path.exists(temp_stego_image_path):
                os.remove(temp_stego_image_path)
                
    return render_template('extract.html', message=decrypted_message_text)

@app.route('/download/<filename>')
@login_required # Protect downloads too if they are sensitive
def download_file(filename):
    # Files in UPLOAD_FOLDER are now uniquely named and potentially temporary stego images
    # Make sure this is secure and only allows intended files.
    # For simplicity, assuming files are in UPLOAD_FOLDER for now.
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path) or not secure_filename(filename) == filename: # Basic check
        flash("File not found or invalid filename.", "danger")
        return redirect(url_for('home'))
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    # Ensure data files exist with headers if they are empty or new
    if not os.path.exists(USER_DATA_FILE) or os.path.getsize(USER_DATA_FILE) == 0:
        with open(USER_DATA_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['username', 'password_hash', 'public_key_pem', 'balance'])
    
    if not os.path.exists(MESSAGE_DATA_FILE) or os.path.getsize(MESSAGE_DATA_FILE) == 0:
        with open(MESSAGE_DATA_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['message_id', 'sender_username', 'recipient_username', 'ipfs_hash', 'timestamp', 'is_read'])

    if not os.path.exists(TRANSACTION_DATA_FILE) or os.path.getsize(TRANSACTION_DATA_FILE) == 0:
        with open(TRANSACTION_DATA_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['transaction_id', 'sender_username', 'recipient_username', 'amount', 'timestamp', 'description'])

    # For production, use a proper WSGI server like Gunicorn or Waitress
    # For development, debug=True is fine. Ensure it's False in production.
    app.run(debug=True, port=5001) # Changed port to avoid conflict if old app is running
