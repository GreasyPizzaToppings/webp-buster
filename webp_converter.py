import os
from PIL import Image

from file_handler import FileHandler

class WebpConverter:
    """
        Handle conversion of webp image to desired output format
    """
    def __init__(self, logger):
        self.logger = logger
        self.config = logger.config

        self.OUTPUT_FORMAT = self.config.get('conversion', 'output_format')
        self.CREATE_BACKUP = self.config.get('conversion', 'create_backup')
        self.BACKUP_EXTENSION = self.config.get('conversion', 'backup_extension')

    def convert_webp(self, source_path, output_path):
        """
        Convert image to the configured output format with proper resource cleanup.
        """
        img = None
        try:
            self.logger.debug(f"Using output format: {self.OUTPUT_FORMAT}")
            output_format = self.OUTPUT_FORMAT.lstrip('.').upper()
            
            # First pass - verify the image
            with Image.open(source_path) as verify_img:
                verify_img.verify()
            
            # Second pass - convert the image
            img = Image.open(source_path)
            if output_format in ('JPEG', 'JPG'):
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
                    
        except Exception as e:
            self.logger.error(f"Error converting {source_path}: {e}")
            return False
        finally:
            if img:
                try:
                    img.close()
                except:
                    pass


    def is_webp_file(self, file_path):
        """
        Check if a file is a valid WebP image by reading its header structure.
        """

        if not FileHandler.is_file_available(file_path):
            self.logger.error(f"Timeout waiting for file to become available: {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                # Read RIFF header (12 bytes)
                header = f.read(12)
                if len(header) < 12:
                    self.logger.debug(f"Skipping file - too short: {file_path}. Header length: {len(header)}")
                    return False
                
                # Check RIFF signature
                if header[:4] != b'RIFF':
                    self.logger.debug(f"Skipping non-WebP file: {file_path}")
                    return False
                    
                # Check WEBP signature
                if header[8:12] != b'WEBP':
                    self.logger.debug(f"Skipping non-WebP file: {file_path}")
                    return False
                
                # Read chunk header (4 bytes)
                chunk_header = f.read(4)
                if len(chunk_header) < 4:
                    return False
                
                # Verify chunk type (VP8, VP8L, or VP8X)
                valid_chunks = {b'VP8 ', b'VP8L', b'VP8X'}
                if chunk_header not in valid_chunks:
                    return False
                
                self.logger.debug(f"Valid WebP file detected: {file_path}")
                return True
                
        except FileNotFoundError:
            # Silently ignore file not found errors as they're common with temporary files
            return False
        except PermissionError:
            self.logger.info(f"Permission denied validating file: {file_path}")
        except Exception as e:
            self.logger.info(f"Error checking file {file_path}: {e}")
        
        return False

