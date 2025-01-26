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
            self.logger.info(f"Converted: {webp_path} -> {png_path}")
        
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
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def monitor_system(paths_to_monitor, pre_conversion_path=None, recursive_mode=False):
    observers = []
    logger = logging.getLogger(__name__)
    
    # Perform pre-conversion on specified path if provided
    if pre_conversion_path:
        webp_handler = WebpHandler(None, recursive_mode, pre_conversion_path)
        webp_handler.find_and_convert_existing_webps(pre_conversion_path)
    
    # Monitor paths (drives or specified paths)
    for path in paths_to_monitor:
        try:
            if not os.path.exists(path):
                logger.error(f"Path does not exist: {path}")
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
    
    return observers

def signal_handler(observers, sig, frame):
    logger = logging.getLogger(__name__)
    logger.info("\nStopping monitoring...")
    for observer in observers:
        observer.stop()
        observer.join()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='WebP to PNG Converter')
    parser.add_argument('-d', '--deep', help='Directory to pre-convert WebP files', type=str)
    parser.add_argument('paths', nargs='*', help='Paths to monitor (optional)')
    
    args = parser.parse_args()

    setup_logging()
    
    # Determine paths to monitor
    paths_to_monitor = args.paths if args.paths else get_available_drives()
    
    observers = monitor_system(
        paths_to_monitor, 
        pre_conversion_path=args.deep, 
        recursive_mode=bool(args.deep)
    )
    
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(observers, sig, frame))
    
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        signal_handler(observers, None, None)

if __name__ == "__main__":
    main()