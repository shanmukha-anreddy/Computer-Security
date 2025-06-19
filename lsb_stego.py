from stegano import lsb

# Hide data in image using default LSB method
import base64

def hide_data_in_image(cover_image_path, encrypted_data, output_path="stego_image.png"):
    # Encode bytes to base64 string for safe hiding
    b64_data = base64.b64encode(encrypted_data).decode('ascii')
    secret_image = lsb.hide(cover_image_path, b64_data)
    secret_image.save(output_path)
    return output_path

# Extract data from image using default LSB method
import re

def extract_data_from_image(stego_image_path):
    hidden = lsb.reveal(stego_image_path)
    if hidden is not None:
        # Check if string is valid base64
        if re.fullmatch(r'[A-Za-z0-9+/=\r\n]+', hidden):
            try:
                return base64.b64decode(hidden.encode('ascii'))
            except Exception:
                return None
        else:
            # Not valid base64, likely an old image or corrupted data
            return None
    return None
