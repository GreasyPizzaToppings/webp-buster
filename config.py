import os
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    'system': {
        'system_folders': [
            '$recycle.bin',
            'recycle.bin',
            'system volume information',
            'temp',
            '$windows.~ws',
            'windowsapps',
            'appdata',
            '$windows.~bt',
            'programdata',
            '$windows.old',
            'windows',
            'program files',
            'program files (x86)'
            'amd',
            'nvidia',

            '.tmp',
            'thumbs.db',
            'desktop.ini',
            '.cache',
            '.local/share',
            'tracker3',
            'gvfs-metadata',
            'thumbnails'
        ],

        'image_file_extensions': [
            '.jpg',  # JPEG image
            '.jpeg', # JPEG image
            '.png',  # Portable Network Graphics
            '.gif',  # Graphics Interchange Format
            '.bmp',  # Bitmap image
            '.tiff', # Tagged Image File Format
            '.tif',  # Tagged Image File Format
            '.webp', # WebP image
            '.raw',  # Raw image format
            '.cr2',  # Canon RAW 2
            '.nef',  # Nikon Electronic Format
            '.arw',  # Sony Alpha RAW
            '.sr2',  # Sony RAW 2
            '.dng',  # Digital Negative
            '.psd',  # Adobe Photoshop Document
            '.ai',   # Adobe Illustrator Artwork
            '.svg',  # Scalable Vector Graphics
            '.ico',  # Icon file
            '.heic', # High Efficiency Image Format (used by iOS)
            '.heif', # High Efficiency Image Format
            '.indd', # Adobe InDesign Document
            '.eps',  # Encapsulated PostScript
            '.pdf',  # Portable Document Format (can contain images)
            '.xcf',  # GIMP image file
            '.kdc',  # Kodak Digital Camera RAW
            '.orf',  # Olympus RAW Format
            '.raf',  # Fujifilm RAW
            '.rw2',  # Panasonic RAW
            '.pef',  # Pentax Electronic File
            '.srf',  # Sony RAW Format
            '.mrw',  # Minolta RAW
            '.dcr',  # Kodak Digital Camera RAW
            '.3fr',  # Hasselblad RAW
            '.fff',  # Imacon RAW
            '.iiq',  # Phase One RAW
            '.rwl',  # Leica RAW
            '.nrw',  # Nikon RAW
            '.ptx',  # Pentax RAW
            '.r3d',  # Redcode RAW
            '.rwz',  # Rawzor compressed RAW
            '.srw',  # Samsung RAW
            '.x3f',  # Sigma RAW
            '.erf',  # Epson RAW
            '.mef',  # Mamiya RAW
            '.mos',  # Leaf RAW
            '.cap',  # Phase One RAW
            '.cs1',  # Capture Shop 1-shot RAW
            '.bay',  # Casio RAW
            '.crw',  # Canon RAW
            '.dng',  # Adobe Digital Negative
            '.drf',  # Kodak Digital Camera RAW
            '.dsc',  # Kodak Digital Camera RAW
            '.k25',  # Kodak K25 RAW
            '.kc2',  # Kodak DCS200 RAW
            '.mdc',  # Minolta RD175 RAW
            '.mrw',  # Minolta DiMAGE RAW
            '.orf',  # Olympus RAW
            '.pcd',  # Kodak Photo CD
            '.pcx',  # PC Paintbrush Exchange
            '.pxn',  # Logitech RAW
            '.raf',  # Fuji RAW
            '.raw',  # Panasonic RAW
            '.rdc',  # Ricoh RAW
            '.rw2',  # Panasonic RAW
            '.sr2',  # Sony RAW
            '.srf',  # Sony RAW
            '.srw',  # Samsung RAW
            '.x3f',  # Sigma RAW
        ],

        'max_file_size_mb': 100,
        'conversion_timeout_seconds': 5,
        'app_directory': '~/WebP_Buster'  # New parameter for the base directory
    },

    'conversion': {
        'delete_source': True,
        'create_backup': False,
        'backup_extension': '.bak',
        'output_format': '.png'  # supported: png, jpeg, bmp, tiff
    
    },
    'logging': {
        'level': 'INFO',
        'max_size_mb': 5,
        'filename': 'converter.log'  # Just the filename instead of full path
    }
}

class Config:
    def __init__(self):
        # Get base directory from config and expand user path
        self.base_dir = Path(DEFAULT_CONFIG['system']['app_directory']).expanduser()
        self.config_path = self.base_dir / 'config.yml'
        self.load_config()
        
        # After loading config, update base_dir in case it was changed in user config
        self.base_dir = Path(self.config['system']['app_directory']).expanduser()
        
        # Ensure the base directory exists
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def load_config(self):
        """Load configuration from file or create default if not exists"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                self.config = self._merge_configs(DEFAULT_CONFIG, user_config)
        else:
            self.config = DEFAULT_CONFIG.copy()
            self._save_default_config()

    def _merge_configs(self, default, user):
        """Deep merge user config with defaults"""
        merged = default.copy()
        for key, value in user.items():
            if key in merged and isinstance(merged[key], dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _save_default_config(self):
        """Save default configuration file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)

    def get(self, *keys):
        """Get configuration value using dot notation"""
        value = self.config
        for key in keys:
            value = value[key]
        return value

    def get_log_path(self):
        """Get the full path to the log file"""
        return self.base_dir / self.config['logging']['filename']