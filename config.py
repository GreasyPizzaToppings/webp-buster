import os
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    'system': {
        'system_folders': [
            '$recycle.bin',
            'system volume information',
            'temp',
            '$windows.~ws',
            'windowsapps',
            'appdata',
            '$windows.~bt',
            'programdata',
            '$windows.old',
            '.tmp',
            'thumbs.db',
            'desktop.ini',
            '.cache',
            '.local/share',
            'tracker3',
            'gvfs-metadata',
            'thumbnails'
        ],
        'max_file_size_mb': 100,
        'conversion_timeout_seconds': 30,
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