#! python
import os
import sys
import time
import signal
import argparse
from PIL import Image
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# our modules
from config import Config
from logger import Logger
from file_handler import FileHandler
from webp_converter import WebpConverter
from directory_monitor import DirectoryMonitor

config = Config()
logger = Logger(config)
converter = WebpConverter(logger)
directory_monitor = DirectoryMonitor(logger)

class WebpBuster(FileSystemEventHandler):

    def __init__(self, monitor_directory):
        """
        Monitor a given directory and bust WebP files
        
        Args:
            monitor_directory (str): Directory to monitor for new WebP files
        """
        self.monitor_directory = monitor_directory
        self.webp_s = set()
        self.created_files = set()

        self.SYSTEM_FOLDERS = config.get('system', 'system_folders')
        self.IMAGE_EXTENSIONS = config.get('system', 'image_file_extensions') # list of common image file extensions
        self.MAX_FILE_SIZE = config.get('system', 'max_file_size_mb') * 1024 * 1024  # Convert MB to bytes
        
        # Load conversion settings
        self.DELETE_SOURCE = config.get('conversion', 'delete_source')
        self.CREATE_BACKUP = config.get('conversion', 'create_backup')
        self.BACKUP_EXTENSION = config.get('conversion', 'backup_extension')
        self.OUTPUT_FORMAT = config.get('conversion', 'output_format')

    def _should_file_be_processed(self, file_path):
        """
        Determine if a file should be processed based on various criteria.
        Optimized to perform fastest checks first.
        """
        # Skip if we created this file (in-memory check)
        if file_path in self.created_files:
            logger.debug(f"Skipping self-created file: {file_path}")
            return False

        # Skip system and cache directories
        lower_path = file_path.lower()
        path_parts = lower_path.replace('\\', '/').split('/')  # normalize and split path
        if any(folder.lower() in path_parts for folder in self.SYSTEM_FOLDERS):
            logger.debug(f"Skipping system/cache path: {file_path}")
            return False

        filename = os.path.basename(file_path)

        if '.' in filename:
            # Split from the right once to get the extension
            file_extension = f".{filename.lower().split('.')[-1]}"

            if file_extension not in self.IMAGE_EXTENSIONS:
                logger.debug(f"Skipping non-image file extension: {file_extension} {file_path}")
                return False

        # check filesize
        try:
            if FileHandler.is_file_available(file_path):
                file_size = os.path.getsize(file_path)
                if file_size >= self.MAX_FILE_SIZE:
                    logger.info(f"file too big: {file_path}")
                return file_size <= self.MAX_FILE_SIZE
            else:
                logger.info(f"File was not available to check file size {file_path}")
        except OSError as e:
            logger.error(f"problem getting file size: {e}")
            return False

    def process_webp_file(self, webp_path):
        """
        Attempt to convert a webp file to desired output and handle cleanup
        
        Returns: True if successful, False if not
        """

        if not self._should_file_be_processed(webp_path):
            return False

        if not converter.is_webp_file(webp_path):
            return False
        
        logger.debug(f"Processing valid WebP file: {webp_path}")
                
        try:
            if not os.path.exists(webp_path):
                return False
            
            if os.path.getsize(webp_path) == 0:
                logger.error(f"Empty file: {webp_path}")
                return False
            
            # Create backup if configured
            if self.CREATE_BACKUP:
                backup_path = webp_path + self.BACKUP_EXTENSION
                try:
                    import shutil
                    shutil.copy2(webp_path, backup_path)
                    self.created_files.add(backup_path)
                except Exception as e:
                    logger.error(f"Failed to create backup of {webp_path}: {e}")
            
            output_path = FileHandler.generate_unique_output_path(webp_path, self.OUTPUT_FORMAT, logger)

            if converter.convert_webp(webp_path, output_path):
                self.created_files.add(output_path)
                # Add a small delay before deletion to ensure all handles are released
                time.sleep(0.1)
                if self.DELETE_SOURCE:
                    # Try multiple times with exponential backoff
                    for attempt in range(3):
                        try:
                            os.remove(webp_path)
                            break
                        except PermissionError:
                            if attempt < 2:  # Don't sleep on last attempt
                                time.sleep(0.2 * (2 ** attempt))
                            else:
                                raise
                    self.webp_s.add(webp_path)
                    logger.log_conversion(webp_path, output_path)
                    return True
                    
        except Exception as e:
            logger.error(
                f"Unexpected error processing {webp_path}: {e}\n"
                f"Error type: {type(e).__name__}\n"
                f"Error details: {sys.exc_info()}"
            )
            return False

    def on_created(self, event):
        """Handle file creation events."""
        self.process_webp_file(event.src_path)

    @classmethod
    def flush_directory(cls, directory_path):
        """
        Pre convert all WebP files in a directory.
        
        Args:
            directory_path (str): Directory to scan for existing WebP files
        """
        handler = cls(monitor_directory=None)  # Create temporary handler for flushing
        
        if not directory_monitor.is_valid_directory(directory_path):
            return
                
        try:
            logger.info(f"Starting webp flush in: {directory_path}")
            conversion_count = 0

            for root, dirs, files in os.walk(directory_path, topdown=True):
                # Modify dirs in place to skip system directories
                dirs[:] = [d for d in dirs if directory_monitor.is_valid_directory(os.path.join(root, d))]
                    
                for file in files:                    
                    full_path = os.path.join(root, file)
                    if handler.process_webp_file(full_path): 
                        conversion_count += 1
            logger.info(f"Flush complete: Converted {conversion_count} webp files")

        except Exception as e:
            logger.error(
                f"Error during webp flush: {e}\n"
                f"Error type: {type(e).__name__}\n"
                f"Error details: {sys.exc_info()}"
            )   

####


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

def monitor_directories(paths_to_monitor):
    """
        Setup WebpHandlers for each directory to monitor
    """
    observers = []
    
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
            webp_handler = WebpBuster(monitor_directory=path)
            
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
        description='WebP Buster - Monitors directories and automatically converts WebP files to (by default) PNG format',
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

    #flush out a directory if specified one
    if args.flush: WebpBuster.flush_directory(args.flush)

    # monitor specified paths only when specified, otherwise monitor all drives
    paths_to_monitor = args.paths if args.paths else DirectoryMonitor.get_available_drives()
    observers = monitor_directories(paths_to_monitor)

    signal.signal(signal.SIGINT, lambda sig, frame: shutdown_observers(observers, sig, frame))
    
    try:
        while True:
            time.sleep(1)
    # backup shutdown mechanism
    except KeyboardInterrupt:
        shutdown_observers(observers, None, None)


if __name__ == "__main__":
    main()