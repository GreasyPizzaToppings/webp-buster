#! python
import os
import string
import ctypes

class DirectoryMonitor:
    """
        Directory monitoring and validation
    """
    def __init__(self, logger):
        self.logger = logger
        self.config = self.logger.config
        self.SYSTEM_FOLDERS = self.config.get('system', 'system_folders')

    def is_valid_directory(self, directory_path):
        """Validate if a directory exists and is accessible."""
        try:
            if not directory_path or not os.path.exists(directory_path):
                return False
                
            if not os.path.isdir(directory_path):
                return False
                
            if not (os.access(directory_path, os.R_OK) and os.access(directory_path, os.W_OK)):
                return False
                
            lower_path = directory_path.lower()
            path_parts = lower_path.replace('\\', '/').split('/')
            if any(folder.lower() in path_parts for folder in self.SYSTEM_FOLDERS):
                return False

            return True
            
        except Exception as e:
            self.logger.error(f"Error validating directory {directory_path}: {e}")
            return False


    @staticmethod
    def get_available_drives():
        """Get list of available drives to monitor."""
        drives = []
        if os.name == 'nt':  # Windows
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                try:
                    if os.path.exists(drive):
                        ctypes.windll.kernel32.GetDiskFreeSpaceExW(drive, None, None, None)
                        drives.append(drive)
                except:
                    pass
        else:  # Unix-like systems
            try:
                common_paths = ['/home', '/media', '/mnt']
                drives.extend(path for path in common_paths 
                            if os.path.exists(path) and os.access(path, os.R_OK))
            except Exception:
                pass
            
            if not drives:
                drives = [os.getcwd()]
        
        return list(dict.fromkeys(drives))