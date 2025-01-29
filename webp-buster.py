#! python
import os
import sys
import time
import signal
import logging
import string
import ctypes
import argparse
from PIL import Image
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class WebpHandler(FileSystemEventHandler):
    def __init__(self, directory, recursive_mode=False, pre_conversion_path=None):
        self.processed_files = set()
        self.recursive_mode = recursive_mode
        self.pre_conversion_path = pre_conversion_path
        self.logger = logging.getLogger(__name__)
        self.system_folders = self._get_system_folders()

    def _get_system_folders(self):
        """Return a set of system folders to ignore."""
        return {
            "$recycle.bin",    # Windows Recycle Bin
            "system volume information",  # Windows System folder
            "temp",            # Temporary files
            "$windows.~ws",    # Windows Update folder
            "windowsapps",     # Windows Store apps
            "appdata",         # Application Data
            "$windows.~bt",    # Windows backup files
            "programdata",     # Program Data
            "$windows.old",    # Old Windows installation
            ".tmp",            # Temporary files
            "thumbs.db",       # Windows thumbnail cache
            "desktop.ini"      # Windows folder settings
    }

    def _is_valid_webp_file(self, path):
        """Check if the file is a valid WebP file to process."""
        path_lower = path.lower()
        return (not os.path.isdir(path) and 
                path_lower.endswith(".webp") and 
                not any(folder in path_lower for folder in self.system_folders)) 

    def _generate_unique_png_path(self, base_path):
        """Generate a unique PNG file path to avoid name collisions."""
        directory = os.path.dirname(base_path)
        filename = os.path.basename(base_path)
        filename_without_ext = os.path.splitext(filename)[0]
        sanitized_filename = self._sanitize_filename(filename_without_ext)
        png_path = os.path.join(directory, f"{sanitized_filename}.png")
        
        counter = 1
        while os.path.exists(png_path):
            png_path = os.path.join(directory, f"{sanitized_filename}_{counter}.png")
            counter += 1
        
        return png_path

    def _convert_image(self, webp_path, png_path):
        """Convert WebP image to PNG format."""
        try:
            with Image.open(webp_path) as img:
                img.verify()
                img = Image.open(webp_path)
                img.save(png_path, "PNG")
            return True
        except Image.UnidentifiedImageError:
            self.logger.error(f"Cannot identify image file: {webp_path}")
        except PermissionError:
            self.logger.error(f"Permission denied for file: {webp_path}")
        return False

    def _log_conversion(self, webp_path, png_path):
        """Log the conversion result with proper Unicode handling."""
        try:
            log_message = f"Converted: {webp_path} -> {os.path.basename(png_path)}"
            self.logger.info(log_message)
        except UnicodeEncodeError:
            log_message = f"Converted: {webp_path.encode('ascii', 'replace').decode()} -> {os.path.basename(png_path).encode('ascii', 'replace').decode()}"
            self.logger.info(log_message)

    def _sanitize_filename(self, filename):
            """
            Remove or replace problematic characters in filenames while preserving Unicode.
            """
            # Characters that are problematic for filesystems
            problematic = {
                '\0': '',       # Null byte
                '/': '_',       # Forward slash
                '\\': '_',      # Back slash
                '<': '(',       # Less than
                '>': ')',       # Greater than
                ':': '-',       # Colon
                '"': "'",       # Double quote
                '|': '-',       # Pipe
                '?': '',        # Question mark
                '*': '',        # Asterisk
                '\n': ' ',      # Newline
                '\r': ' ',      # Carriage return
                '\t': ' ',      # Tab
            }
            
            # Replace problematic characters
            for bad, good in problematic.items():
                filename = filename.replace(bad, good)
            
            # Remove leading/trailing spaces and dots
            filename = filename.strip('. ')
            
            # Ensure filename isn't empty after sanitization
            if not filename:
                filename = 'unnamed'
            
            return filename


    def on_created(self, event):
        if self._is_valid_webp_file(event.src_path):
            self.logger.debug(f"Processing file: {event.src_path}")
            self.convert_and_delete(event.src_path)


    def convert_and_delete(self, webp_path):
        try:
            time.sleep(1)  # wait for file to be fully written
            
            if not os.path.exists(webp_path):
                self.logger.error(f"File not found: {webp_path}")
                return
            
            if os.path.getsize(webp_path) == 0:
                self.logger.error(f"Empty file: {webp_path}")
                return
            
            png_path = self._generate_unique_png_path(webp_path)
            
            if self._convert_image(webp_path, png_path):
                os.remove(webp_path)
                self.processed_files.add(webp_path)
                self._log_conversion(webp_path, png_path)
                
        except Exception as e:
            self.logger.error(
                f"Unexpected error processing {webp_path}: {e}\n"
                f"Error type: {type(e).__name__}\n"
                f"Error details: {sys.exc_info()}"
            )


    def find_and_convert_existing_webps(self, start_path):
        if not self.pre_conversion_path:
            return
        
        for root, _, files in os.walk(self.pre_conversion_path):
            for file in files:
                if file.lower().endswith('.webp'):
                    full_path = os.path.join(root, file)
                    self.convert_and_delete(full_path)


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
        drives = ['/']
    return drives


def setup_logging():
    """Set up logging with proper Unicode support."""
    log_dir = os.path.join(os.path.expanduser('~'), 'WebP_Converter_Logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'webp_converter.log')
    
    # Create a UTF-8 file handler
    file_handler = logging.FileHandler(log_file, 'a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s: %(message)s',
        datefmt='%d-%m-%Y %H:%M'
    ))
    
    # Create a stream handler that can handle Unicode
    # Force UTF-8 encoding for Windows console
    if os.name == 'nt':  # Windows
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s: %(message)s',
        datefmt='%d-%m-%Y %H:%M'
    ))
    
    # Set up the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    
    return logger


def monitor_system(paths_to_monitor, pre_conversion_path=None, recursive_mode=False):
    observers = []
    logger = logging.getLogger(__name__)
    
    # Validate pre-conversion path if provided
    if pre_conversion_path:
        if not os.path.exists(pre_conversion_path):
            logger.error(f"Pre-conversion path does not exist: {pre_conversion_path}")
            sys.exit(1)
        elif not os.path.isdir(pre_conversion_path):
            logger.error(f"Pre-conversion path is not a directory: {pre_conversion_path}")
            sys.exit(1)
        else:
            webp_handler = WebpHandler(None, recursive_mode, pre_conversion_path)
            webp_handler.find_and_convert_existing_webps(pre_conversion_path)
    
    # Validate and monitor paths (drives or specified paths)
    for path in paths_to_monitor:
        try:
            if not os.path.exists(path):
                logger.error(f"Path does not exist: {path}")
                continue
            elif not os.path.isdir(path):
                logger.error(f"Path is not a directory: {path}")
                continue

            observer = Observer()
            webp_handler = WebpHandler(path, recursive_mode)
            
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
    logger = logging.getLogger(__name__)
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
    # Strip any whitespace
    path = path.strip()
    
    # Check if the path is just a drive letter (e.g., "C:")
    if len(path) == 2 and path[1] == ':':
        # Append a slash to make it the root directory
        path = path + '\\'
    
    # Normalize the path
    path = os.path.normpath(path)
    
    return path


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

    setup_logging()
    
    # monitor specified paths only when specified, otherwise monitor all drives
    paths_to_monitor = args.paths if args.paths else get_available_drives()
    
    observers = monitor_system(
        paths_to_monitor, 
        pre_conversion_path=args.flush, 
        recursive_mode=bool(args.flush)  
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