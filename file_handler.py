#! python
import os
import time

class FileHandler:
    """
        Handle file operations, like if is available, generating name, generating output path
    """

    @staticmethod
    def is_file_available(file_path, timeout=3, initial_delay=0.1, file_size_delay=0.1, check_constant_size=True):
        """
        Wait for a file to become available for reading with exponential backoff.
        
        Args:
            file_path: Path to the file to check
            timeout: Maximum time to wait in seconds
            initial_delay: Initial delay between checks in seconds
            file_size_delay: The delay used to check if filesize is stable
            check_constant_size: Whether to verify file size remains constant
            
        Returns:
            bool: True if file becomes available, False if timeout occurs
        """
        start_time = time.time()
        current_delay = initial_delay

        while time.time() - start_time < timeout:
            try:
                # Try to open file for reading in binary mode
                with open(file_path, 'rb') as f:
                    # Try to get an exclusive lock (non-blocking)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    
                    size1 = os.path.getsize(file_path)
                    if size1 <= 0:
                        continue  # Skip to next iteration if file is empty
                    
                    if not check_constant_size:
                        return True
                    
                    # Check if file size is stable
                    time.sleep(file_size_delay)
                    size2 = os.path.getsize(file_path)
                    if size1 == size2:
                        return True
                    
            except (IOError, OSError):
                # File is not yet available or is locked
                pass
                
            # Exponential backoff with maximum delay cap
            time.sleep(min(current_delay, 1.0))
            current_delay *= 2
            
        return False

    @staticmethod
    def generate_unique_output_path(base_path, output_format, logger):
        """
        Generate a unique output file path to avoid name collisions.
        
        Args:
            base_path: Original file path
            output_format: Desired output format (e.g., '.png')
            
        Returns:
            str: Unique file path
        """
        directory = os.path.dirname(base_path)
        filename = os.path.basename(base_path)
        filename_without_ext = os.path.splitext(filename)[0]
        sanitized_filename = FileHandler.sanitize_filename(filename_without_ext, logger)
        output_path = os.path.join(directory, f"{sanitized_filename}{output_format}")
        
        counter = 1
        while os.path.exists(output_path):
            output_path = os.path.join(directory, f"{sanitized_filename}_{counter}{output_format}")
            counter += 1
        
        return output_path

    @staticmethod
    def sanitize_filename(filename, logger):
        """
        Sanitize filename to be safe across operating systems.
        
        Args:
            filename: Original filename
            
        Returns:
            str: Sanitized filename
        """
        if not filename:
            return "unnamed_file"
        
        MAX_LENGTH = 255 
        MIN_LENGTH = 1 
        EFFECTIVE_MAX_LENGTH = MAX_LENGTH - 10
        
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
            sanitized = ' '.join(sanitized.split())
            sanitized = '.'.join(filter(None, sanitized.split('.')))
            
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
                ext = ext[:10] if len(ext) > 10 else ext
                max_name_length = EFFECTIVE_MAX_LENGTH - len(ext) - 1
                if len(name) > max_name_length:
                    name = name[:max_name_length]
                sanitized = f"{name}.{ext}"
            else:
                if len(sanitized) > EFFECTIVE_MAX_LENGTH:
                    sanitized = sanitized[:EFFECTIVE_MAX_LENGTH]
            
            sanitized = ' '.join(sanitized.split())
            sanitized = '.'.join(filter(None, sanitized.split('.')))
            sanitized = sanitized.rstrip('. ')
            
            return sanitized if sanitized else "unnamed_file"
        
        except Exception as e:
            logger.error(f"Error sanitizing filename '{filename}': {e}")
            return "unnamed_file"