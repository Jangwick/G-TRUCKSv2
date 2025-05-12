"""
Script to create the necessary logo files if they don't exist already.
This ensures we have both a regular logo and a light version for dark backgrounds.
"""

import os
from PIL import Image, ImageDraw, ImageFont

def create_placeholder_logo(output_path, text="G-TRUCKS", is_light=False):
    """Create a simple placeholder logo image with text."""
    width, height = 300, 100
    background_color = (0, 120, 60) if not is_light else (20, 160, 80)
    text_color = (255, 255, 255) if not is_light else (255, 255, 255)
    
    image = Image.new('RGBA', (width, height), background_color)
    draw = ImageDraw.Draw(image)
    
    # Try to use a system font or use default
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except IOError:
        font = ImageFont.load_default()
    
    # Calculate text position for centering
    text_width = draw.textlength(text, font=font)
    text_position = ((width - text_width) / 2, (height - 40) / 2)
    
    # Draw the text
    draw.text(text_position, text, font=font, fill=text_color)
    
    # Add an icon/symbol
    draw.rectangle((20, 35, 50, 65), fill=(255, 255, 0) if is_light else (240, 240, 0))
    
    # Save the image
    image.save(output_path)
    print(f"Created placeholder logo: {output_path}")

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define logo paths
    standard_logo_path = os.path.join(current_dir, 'logo.png')
    light_logo_path = os.path.join(current_dir, 'logo-light.png')
    
    # Create standard logo if it doesn't exist
    if not os.path.exists(standard_logo_path):
        create_placeholder_logo(standard_logo_path)
    
    # Create light logo if it doesn't exist
    if not os.path.exists(light_logo_path):
        create_placeholder_logo(light_logo_path, is_light=True)

if __name__ == "__main__":
    main()
