#! python
import os
import sys
import time
import signal
import logging
import string
import ctypes
import shlex
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

    def on_created(self, event):
        if (not event.is_directory and 
            event.src_path.lower().endswith(".webp") and 
            "$RECYCLE.BIN" not in event.src_path):
            self.convert_and_delete(event.src_path)

    def convert_and_delete(self, webp_path):
        if webp_path in self.processed_files:
            return
        try:
            time.sleep(0.5)
            png_path = os.path.splitext(webp_path)[0] + ".png"
            
            if not os.path.exists(webp_path):
                self.logger.error(f"File not found: {webp_path}")
                return
            
            if os.path.getsize(webp_path) == 0:
                self.logger.error(f"Empty file: {webp_path}")
                return
            
            try:
                with Image.open(webp_path) as img:
                    img.verify()
                    img = Image.open(webp_path)
                    img.save(png_path, "PNG")
            except Image.UnidentifiedImageError:
                self.logger.error(f"Cannot identify image file: {webp_path}")
                return
            except PermissionError:
                self.logger.error(f"Permission denied for file: {webp_path}")
                return
            
            os.remove(webp_path)
            self.processed_files.add(webp_path)
            # log just the filename for the output file
            self.logger.info(f"Converted: {webp_path} -> {os.path.basename(png_path)}")
        
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
    log_dir = os.path.join(os.path.expanduser('~'), 'WebP_Converter_Logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'webp_converter.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s: %(message)s',
        datefmt='%d-%m-%Y %H:%M',  # exclude seconds and milliseconds
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

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
    # Strip trailing slashes and normalize slashes
    path = os.path.normpath(path.strip())
    return path


def main():
    parser = argparse.ArgumentParser(
        description='WebP to PNG Converter - Monitors directories and automatically converts WebP files to PNG format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  webp-buster.py                     # Monitor all drives for new WebP files
  webp-buster.py /dir1 /dir2 ...     # Monitor specific directories
  webp-buster.py -f /path/to/dir     # Flush out (convert) existing WebP files in directory, then monitor all drives
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
            time.sleep(5)
    # backup shutdown mechanism
    except KeyboardInterrupt:
        shutdown_observers(observers, None, None)

if __name__ == "__main__":
    main()