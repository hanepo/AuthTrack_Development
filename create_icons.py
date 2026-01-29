#!/usr/bin/env python3
"""Create simple PNG icons for Chrome extension"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, filename):
    # Create image with blue background
    img = Image.new('RGB', (size, size), color='#3B82F6')
    draw = ImageDraw.Draw(img)
    
    # Draw a white border
    border_width = max(1, size // 16)
    draw.rectangle(
        [(border_width, border_width), (size - border_width, size - border_width)],
        outline='white',
        width=border_width
    )
    
    # Draw network icon (simplified)
    center = size // 2
    node_radius = size // 8
    
    # Center node
    draw.ellipse(
        [(center - node_radius, center - node_radius), 
         (center + node_radius, center + node_radius)],
        fill='white'
    )
    
    # Corner nodes
    corner_offset = size // 3
    for dx, dy in [(-1, -1), (1, -1), (-1, 1), (1, 1)]:
        x = center + dx * corner_offset
        y = center + dy * corner_offset
        r = node_radius // 2
        draw.ellipse([(x - r, y - r), (x + r, y + r)], fill='white')
        # Lines to center
        draw.line([(center, center), (x, y)], fill='white', width=max(1, size // 32))
    
    # Save
    img.save(filename, 'PNG')
    print(f"Created {filename}")

# Create icons directory
icons_dir = os.path.join(os.path.dirname(__file__), 'extension', 'icons')
os.makedirs(icons_dir, exist_ok=True)

# Create icons
create_icon(16, os.path.join(icons_dir, 'icon16.png'))
create_icon(48, os.path.join(icons_dir, 'icon48.png'))
create_icon(128, os.path.join(icons_dir, 'icon128.png'))

print("\n✅ All icons created successfully!")
print("📁 Location:", icons_dir)
