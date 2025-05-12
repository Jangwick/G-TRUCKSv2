import os
import json
import time
from werkzeug.utils import secure_filename

# Avatar storage configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def get_upload_folder(app_root_path):
    """Get the upload folder path and ensure it exists"""
    upload_dir = os.path.join(app_root_path, 'static', 'uploads', 'avatars')
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def get_mapping_file(app_root_path):
    """Get the mapping file path"""
    upload_dir = get_upload_folder(app_root_path)
    return os.path.join(upload_dir, 'avatar_mapping.json')

def allowed_file(filename):
    """Check if the file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_avatar(app_root_path, user_id):
    """Get the avatar filename for a user"""
    map_file = get_mapping_file(app_root_path)
    
    # Debug information
    print(f"Getting avatar for user {user_id} from {map_file}")
    
    if not os.path.exists(map_file):
        print(f"Avatar mapping file {map_file} not found - returning None")
        return None
        
    try:
        with open(map_file, 'r') as f:
            avatar_map = json.load(f)
        
        avatar_file = avatar_map.get(str(user_id))
        
        if (avatar_file):
            # Verify the file exists
            upload_dir = get_upload_folder(app_root_path)
            avatar_path = os.path.join(upload_dir, avatar_file)
            
            if os.path.exists(avatar_path):
                print(f"Found avatar for user {user_id}: {avatar_file}")
                return avatar_file
            else:
                print(f"Avatar file {avatar_path} not found on disk")
        
        print(f"No avatar found for user {user_id} in mapping")
        return None
    except Exception as e:
        print(f"Error getting avatar: {str(e)}")
        return None

def save_avatar(app_root_path, user_id, file):
    """Save an avatar file for a user and return the filename"""
    if not file or not allowed_file(file.filename):
        print(f"Invalid file for user {user_id}")
        return None
    
    try:
        # Create a unique filename with timestamp
        timestamp = int(time.time())
        filename = secure_filename(f"user_{user_id}_{timestamp}_{file.filename}")
        
        # Ensure upload directory exists
        upload_dir = get_upload_folder(app_root_path)
        file_path = os.path.join(upload_dir, filename)
        
        # Save the file
        file.save(file_path)
        print(f"Saved avatar for user {user_id} to {file_path}")
        
        # Verify the file was saved
        if not os.path.exists(file_path):
            print(f"Failed to save file {file_path}")
            return None
            
        print(f"File size: {os.path.getsize(file_path)} bytes")
        
        # Update the avatar mapping
        map_file = get_mapping_file(app_root_path)
        avatar_map = {}
        
        if os.path.exists(map_file):
            try:
                with open(map_file, 'r') as f:
                    avatar_map = json.load(f)
            except json.JSONDecodeError:
                print(f"Invalid JSON in {map_file} - creating new mapping")
        
        # Update the mapping with the new avatar
        avatar_map[str(user_id)] = filename
        
        with open(map_file, 'w') as f:
            json.dump(avatar_map, f)
        
        print(f"Updated avatar mapping for user {user_id}: {filename}")
        return filename
    except Exception as e:
        print(f"Error saving avatar: {str(e)}")
        return None
