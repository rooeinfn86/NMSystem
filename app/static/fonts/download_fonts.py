import os
import requests

def download_font(url, filename):
    response = requests.get(url)
    if response.status_code == 200:
        with open(filename, 'wb') as f:
            f.write(response.content)
        print(f"Downloaded {filename}")
    else:
        print(f"Failed to download {filename}")

# Create fonts directory if it doesn't exist
os.makedirs(os.path.dirname(__file__), exist_ok=True)

# Download DejaVu fonts
fonts = {
    'DejaVuSansCondensed.ttf': 'https://github.com/dejavu-fonts/dejavu-fonts/raw/master/ttf/DejaVuSansCondensed.ttf',
    'DejaVuSansCondensed-Bold.ttf': 'https://github.com/dejavu-fonts/dejavu-fonts/raw/master/ttf/DejaVuSansCondensed-Bold.ttf',
    'DejaVuSansCondensed-Oblique.ttf': 'https://github.com/dejavu-fonts/dejavu-fonts/raw/master/ttf/DejaVuSansCondensed-Oblique.ttf',
    'DejaVuSansCondensed-BoldOblique.ttf': 'https://github.com/dejavu-fonts/dejavu-fonts/raw/master/ttf/DejaVuSansCondensed-BoldOblique.ttf'
}

for filename, url in fonts.items():
    filepath = os.path.join(os.path.dirname(__file__), filename)
    download_font(url, filepath) 