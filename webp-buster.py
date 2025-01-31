#! python
import os
import sys
import time
import signal
import string
import ctypes
import argparse
from PIL import Image
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# our modules
from config import Config
from logger import Logger

config = Config()
logger = Logger(config)

class WebpHandler(FileSystemEventHandler):

    def __init__(self, monitor_directory):
        """
        Initialize WebP handler with a directory to monitor.
        
        Args:
            monitor_directory (str): Directory to monitor for new WebP files
        """
        self.monitor_directory = monitor_directory
        self.webp_s = set()
        self.created_files = set()
        config = Config()

        # Load system folders from config
        self.SYSTEM_FOLDERS = config.get('system', 'system_folders')
        self.MAX_FILE_SIZE = config.get('system', 'max_file_size_mb') * 1024 * 1024  # Convert MB to bytes
        self.CONVERSION_TIMEOUT = config.get('system', 'conversion_timeout_seconds')
        
        # Load conversion settings
        self.DELETE_SOURCE = config.get('conversion', 'delete_source')
        self.CREATE_BACKUP = config.get('conversion', 'create_backup')
        self.BACKUP_EXTENSION = config.get('conversion', 'backup_extension')
        self.OUTPUT_FORMAT = config.get('conversion', 'output_format')

    def _is_valid_directory(self, directory_path):
        """
        Validate if a directory exists and is accessible.
        """
        try:
            if not directory_path:
                logger.error("No directory path specified")
                return False
                
            if not os.path.exists(directory_path):
                logger.error(f"Directory does not exist: {directory_path}")
                return False
                
            if not os.path.isdir(directory_path):
                logger.error(f"Path is not a directory: {directory_path}")
                return False
                
            if not (os.access(directory_path, os.R_OK) and os.access(directory_path, os.W_OK)):
                logger.error(f"No read and write permission for directory: {directory_path}")
                return False
                
            return True
            
        except PermissionError as e:
            logger.error(f"Permission denied accessing directory: {directory_path}. Error: {e}")
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error validating directory {directory_path}: {e}\n"
                f"Error type: {type(e).__name__}\n"
                f"Error details: {sys.exc_info()}"
            )
            return False

    def _should_file_be_processed(self, file_path):
        """
        Determine if a file should be processed based on various criteria.
        """
        # Skip directories
        if os.path.isdir(file_path):
            logger.debug(f"Skipping directory: {file_path}")
            return False

        # Skip if we created this file
        if file_path in self.created_files:
            logger.info(f"Skipping self-created file: {file_path}")
            return False

        # Check file size
        try:
            if os.path.getsize(file_path) > self.MAX_FILE_SIZE:
                logger.info(f"Skipping file exceeding size limit: {file_path}")
                return False
        except OSError:
            return False

        # Skip system and cache directories
        lower_path = file_path.lower()
        if any(folder.lower() in lower_path for folder in self.SYSTEM_FOLDERS):
            logger.debug(f"Skipping system/cache path: {file_path}")
            return False
        
        # Skip temporary files and specific patterns
        basename = os.path.basename(lower_path)
        if (basename.endswith('.tmp') or     # Temporary files
            '.' in basename.split('.')[-1]): # Files with additional extensions after the main one
            logger.info(f"Skipping temporary or system file: {file_path}")
            return False

        return True

    def _is_valid_webp_file(self, file_path):
        """
        Check if a file is a valid WebP image by reading its header structure.
        """
        if not self._should_file_be_processed(file_path):
            return False

        time.sleep(1)  # wait for file to be fully written

        try:
            with open(file_path, 'rb') as f:
                # Read RIFF header (12 bytes)
                header = f.read(12)
                if len(header) < 12:
                    logger.info(f"Skipping file - too short: {file_path}. Header length: {len(header)}")
                    return False
                
                # Check RIFF signature
                if header[:4] != b'RIFF':
                    logger.info(f"Skipping non-WebP file: {file_path}")
                    return False
                    
                # Check WEBP signature
                if header[8:12] != b'WEBP':
                    logger.info(f"Skipping non-WebP file: {file_path}")
                    return False
                
                # Read chunk header (4 bytes)
                chunk_header = f.read(4)
                if len(chunk_header) < 4:
                    return False
                
                # Verify chunk type (VP8, VP8L, or VP8X)
                valid_chunks = {b'VP8 ', b'VP8L', b'VP8X'}
                if chunk_header not in valid_chunks:
                    return False
                
                logger.info(f"Valid WebP file detected: {file_path}")
                return True
                
        except FileNotFoundError:
            # Silently ignore file not found errors as they're common with temporary files
            return False
        except PermissionError:
            logger.info(f"Permission denied: {file_path}")
        except Exception as e:
            logger.info(f"Error checking file {file_path}: {e}")
        
        return False

    def _generate_unique_output_path(self, base_path):
        """Generate a unique output file path to avoid name collisions."""
        directory = os.path.dirname(base_path)
        filename = os.path.basename(base_path)
        filename_without_ext = os.path.splitext(filename)[0]
        sanitized_filename = self._sanitize_filename(filename_without_ext)
        output_path = os.path.join(directory, f"{sanitized_filename}{self.OUTPUT_FORMAT}")
        
        counter = 1
        while os.path.exists(output_path):
            output_path = os.path.join(directory, f"{sanitized_filename}_{counter}{self.OUTPUT_FORMAT}")
            counter += 1
        
        return output_path

    def _convert_image(self, webp_path, output_path):
        """
        Convert WebP image to the configured output format.
        The output format is specified in config.yml without the dot (e.g., 'PNG', 'JPEG', etc.)
        """
        try:
            logger.debug(f"Using output format: {self.OUTPUT_FORMAT}")  # Changed from INFO to debug

            # Get output format from file extension, removing the dot and converting to uppercase
            output_format = self.OUTPUT_FORMAT.lstrip('.').upper()
            
            with Image.open(webp_path) as img:
                img.verify()

                img = Image.open(webp_path)
                
                # Handle JPEG conversion specifically since it doesn't support transparency
                if output_format == 'JPEG' or output_format == 'JPG':
                    # Convert to RGB mode if image has transparency
                    if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
                        background = Image.new('RGB', img.size, 'white')
                        if img.mode == 'P':
                            img = img.convert('RGBA')
                        background.paste(img, mask=img.split()[-1])
                        img = background
                    img.save(output_path, 'JPEG', quality=95)
                else:
                    img.save(output_path, output_format)
                return True
                
        except Image.UnidentifiedImageError:
            logger.error(f"Cannot identify image file: {webp_path}")
        except ValueError as e:
            logger.error(f"Invalid or unsupported output format '{output_format}' for file: {webp_path}. Error: {e}")
        except PermissionError:
            logger.error(f"Permission denied for file: {webp_path}")
        except Exception as e:
            logger.error(f"Error converting {webp_path}: {e}")
        return False

    def _log_conversion(self, webp_path, png_path):
        """Log the conversion result with proper Unicode handling."""
        try:
            log_message = f"Converted: {webp_path} -> {os.path.basename(png_path)}"
            logger.info(log_message)
        except UnicodeEncodeError:
            log_message = f"Converted: {webp_path.encode('ascii', 'replace').decode()} -> {os.path.basename(png_path).encode('ascii', 'replace').decode()}"
            logger.info(log_message)

    def _sanitize_filename(self, filename):
        """
        Sanitize filename to be safe across operating systems, removing problematic characters
        while preserving meaningful content.
        """
        if not filename:
            return "unnamed_file"
        
        MAX_LENGTH = 255 
        MIN_LENGTH = 1 
        
        # Reserve space for potential suffix (e.g., "_1" for duplicates)
        EFFECTIVE_MAX_LENGTH = MAX_LENGTH - 10
        
        # Characters explicitly forbidden in most filesystems
        forbidden_chars = {
            '<': '(',
            '>': ')',
            ':': '-',
            '"': "'",
            '/': '_',
            '\\': '_',
            '|': '-',
            '?': '',
            '*': '',
            '^': '',
            '&': 'and',
            '$': '',
            '#': '',
            '`': "'",
            '~': '-',
            '+': 'plus',
            '=': 'equals',
            '%': 'percent',
            ';': ',',
            '!': '',
        }
        
        try:
            sanitized = str(filename).strip()
            
            # Replace forbidden characters
            for bad, good in forbidden_chars.items():
                sanitized = sanitized.replace(bad, good)
            
            # Remove non-printing characters and control characters
            sanitized = ''.join(char for char in sanitized 
                            if char.isprintable() and ord(char) < 0xFFFF)
            
            # Replace multiple spaces/dots with single ones
            sanitized = ' '.join(sanitized.split())  # Normalize spaces
            sanitized = '.'.join(filter(None, sanitized.split('.')))  # Normalize dots
            
            # Remove leading/trailing dots and spaces
            sanitized = sanitized.strip('. ')
            
            # Replace any remaining unsafe characters with underscores
            sanitized = ''.join(char if char.isalnum() or char in ' .-_(),' else '_' 
                            for char in sanitized)
            
            # Ensure minimum length
            if not sanitized or len(sanitized.strip()) < MIN_LENGTH:
                sanitized = "unnamed_file"
            
            # Enforce maximum length while preserving extension
            name_parts = sanitized.rsplit('.', 1)
            if len(name_parts) > 1:
                name, ext = name_parts
                # If extension is too long, truncate it
                ext = ext[:10] if len(ext) > 10 else ext
                # Calculate available space for name
                max_name_length = EFFECTIVE_MAX_LENGTH - len(ext) - 1
                if len(name) > max_name_length:
                    name = name[:max_name_length]
                sanitized = f"{name}.{ext}"
            else:
                # No extension
                if len(sanitized) > EFFECTIVE_MAX_LENGTH:
                    sanitized = sanitized[:EFFECTIVE_MAX_LENGTH]
            
            # final cleanup of multiple dots and spaces
            sanitized = ' '.join(sanitized.split())
            sanitized = '.'.join(filter(None, sanitized.split('.')))
            
            # Ensure we don't end with a dot or space
            sanitized = sanitized.rstrip('. ')
            
            return sanitized if sanitized else "unnamed_file"
        
        except Exception as e:
            logger.error(f"Error sanitizing filename '{filename}': {e}")
            return "unnamed_file"

    def convert_and_delete_webp(self, webp_path):
        """Attempt to convert a webp file to desired output and handle cleanup"""
        if not self._is_valid_webp_file(webp_path):
            return
        
        logger.debug(f"Processing valid WebP file: {webp_path}")
            
        try:
            if not os.path.exists(webp_path):
                return
            
            if os.path.getsize(webp_path) == 0:
                logger.error(f"Empty file: {webp_path}")
                return
            
            # Create backup if configured
            if self.CREATE_BACKUP:
                backup_path = webp_path + self.BACKUP_EXTENSION
                try:
                    import shutil
                    shutil.copy2(webp_path, backup_path)
                    self.created_files.add(backup_path)
                except Exception as e:
                    logger.error(f"Failed to create backup of {webp_path}: {e}")
            
            output_path = self._generate_unique_output_path(webp_path)
            
            if self._convert_image(webp_path, output_path):
                self.created_files.add(output_path)
                if self.DELETE_SOURCE:
                    os.remove(webp_path)
                self.webp_s.add(webp_path)
                self._log_conversion(webp_path, output_path)
                
        except Exception as e:
            logger.error(
                f"Unexpected error processing {webp_path}: {e}\n"
                f"Error type: {type(e).__name__}\n"
                f"Error details: {sys.exc_info()}"
            )

    def on_created(self, event):
        """Handle file creation events."""
        self.convert_and_delete_webp(event.src_path)

    @classmethod
    def flush_directory(cls, directory_path):
        """
        Class method to flush (convert) all WebP files in a directory.
        
        Args:
            directory_path (str): Directory to scan for existing WebP files
        """
        handler = cls(monitor_directory=None)  # Create temporary handler for flushing
        
        if not handler._is_valid_directory(directory_path):
            return
            
        try:
            logger.info(f"Starting webp flush in: {directory_path}")
            
            for root, _, files in os.walk(directory_path):
                for file in files:                    
                    full_path = os.path.join(root, file)
                    handler.convert_and_delete_webp(full_path)
                            
        except Exception as e:
            logger.error(
                f"Error during webp flush: {e}\n"
                f"Error type: {type(e).__name__}\n"
                f"Error details: {sys.exc_info()}"
            )

####

def get_available_drives():
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
        # Get all root level directories
        try:
            # Always include these critical paths
            common_paths = ['/home', '/media', '/mnt']
            drives.extend(path for path in common_paths if os.path.exists(path) and os.access(path, os.R_OK))
            
            ''' uncomment if you want WHOLE system monitoring
            # Add all readable directories from root
            for item in os.listdir('/'):
                full_path = os.path.join('/', item)
                if os.path.isdir(full_path) and os.access(full_path, os.R_OK):
                    if not os.path.islink(full_path):  # Skip symbolic links
                        drives.append(full_path)
            '''
        except Exception:
            pass
        
        # If no paths are accessible, default to current directory
        if not drives:
            drives = [os.getcwd()]
    
    # Remove duplicates while preserving order
    return list(dict.fromkeys(drives))

def monitor_system(paths_to_monitor, flush_directory=None):
    observers = []
    
    if flush_directory:
        WebpHandler.flush_directory(flush_directory)
    
    # Set up monitoring for specified paths
    for path in paths_to_monitor:
        try:
            if not os.path.exists(path):
                logger.error(f"Path does not exist: {path}")
                continue
            elif not os.path.isdir(path):
                logger.error(f"Path is not a directory: {path}")
                continue

            observer = Observer()
            webp_handler = WebpHandler(monitor_directory=path)
            
            observer.schedule(webp_handler, path, recursive=True)
            observer.start()
            observers.append(observer)
            logger.info(f"Successfully monitoring {path}")

        except PermissionError as e:
            logger.error(f"Permission error monitoring {path}: {e}")
        except Exception as e:
            logger.error(f"Detailed error monitoring {path}: {e}")

    if not observers:
        logger.error("No valid paths to monitor. Shutting down.")
        sys.exit(1)

    return observers


def shutdown_observers(observers, _signum=None, _frame=None):
    """Gracefully stop all filesystem observers and exit the program.
    
    Args:
        observers: List of Observer objects to stop
        _signum: Unused signal number (required by signal handler signature)
        _frame: Unused current stack frame (required by signal handler signature)
    """
    logger.info("Shutting down monitoring...")
    
    for observer in observers:
        try:
            if observer.is_alive():
                observer.stop()
                observer.join(timeout=5)
                if observer.is_alive():
                    logger.warning(f"Observer for {observer.paths} didn't terminate cleanly")
        except Exception as e:
            logger.error(f"Error stopping observer: {e}")
    
    logger.info("Clean shutdown complete")
    sys.exit(0)


def normalize_path(path):
    """Normalize path to handle Windows paths with forward/backward slashes and trailing slashes"""
    path = path.strip()
    
    # Check if the path is just a drive letter (e.g., "C:")
    if len(path) == 2 and path[1] == ':':
        # Append a slash to make it the root directory
        path = path + '\\'
    
    return os.path.normpath(path)


def main():
    parser = argparse.ArgumentParser(
        description='WebP to PNG Converter - Monitors directories and automatically converts WebP files to PNG format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  webp-buster.py                        # Monitor all drives for new WebP files
  webp-buster.py /dir1 /dir2 ...        # Monitor specific directories
  webp-buster.py -f /path/to/dir        # Flush out (convert) existing WebP files in directory, then monitor all drives
  webp-buster.py -f /dir1 /dir2 /dir3   # Flush out (convert) existing WebP files in dir1, then monitor dir2 and dir3
        """
    )
    parser.add_argument(
        '-f', '--flush', 
        help='First flush out (convert) all existing WebP files in the specified directory before monitoring the specified paths.',
        type=normalize_path,
        metavar='DIR'
    )
    parser.add_argument(
        'paths', 
        nargs='*', 
        help='Paths to monitor for new WebP files (if none specified, monitors all drives)',
        type=normalize_path
    )
    
    args = parser.parse_args()

    # monitor specified paths only when specified, otherwise monitor all drives
    paths_to_monitor = args.paths if args.paths else get_available_drives()
    
    observers = monitor_system(
        paths_to_monitor, 
        flush_directory=args.flush
    )

    signal.signal(signal.SIGINT, lambda sig, frame: shutdown_observers(observers, sig, frame))
    
    try:
        while True:
            time.sleep(1)
    # backup shutdown mechanism
    except KeyboardInterrupt:
        shutdown_observers(observers, None, None)


if __name__ == "__main__":
    main()