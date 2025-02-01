# webp-buster
Automatically converts WebP files to PNG/JPG/BMP/TIFF format by monitoring directories.

## Requirements
- `Watchdog` for filesystem monitoring
- `Pillow` for image processing
- `PyYAML` for YAML config file
- `pywin32` for windows
- `Python 3.7+`

Install using `pip install -r requirements.txt`

##  Usage
`python webp-buster.py [-h] [-f DIR] [paths ...]`

WebP Buster - Monitors directories and automatically converts WebP files to (by default) PNG format

positional arguments:
- `paths`              Paths to monitor for new WebP files (if none specified,
                       monitors all drives)

options:
-  `-h`, `--help`           show this help message and exit
-  `-f DIR`, `--flush DIR`  First flush out (convert) all existing WebP files in
                       the specified directory before monitoring the specified
                       paths.

Examples:
- `webp-buster.py` Monitor all drives for new WebP files
- `webp-buster.py /dir1 /dir2 ...` Monitor specific directories
- `webp-buster.py -f /path/to/dir` Flush out (convert) existing WebP files in directory, then monitor all drives
- `webp-buster.py -f /path/to/dir /dir1 /dir2` Flush out (convert) existing WebP files in a directory, then monitor two other directories

## Configuration
Webp Buster allows you to configure various features and settings located in ~/Webp_Buster/config.yaml
- `output_format` the file type to output to. Supported: png, jpeg, bmp, tiff. Default = .png
- `system_folders` folders to ignore. set to some common system folders by default (like system32 and $recycle.bin)
- `app_directory` directory for configuration and logging files. Set to ~/Webp_Buster/ by default
- `delete_source` whether or not to delete the original WebP file. Default = True
- `create_backup` whether or not to create a backup of the original WebP file with a .bak extension. Default = False
  
## Logging
Logs outputs to stdout (console) and to a file located in ~/WebP_Buster/converter.log

## Example usage of flushing a directory and then monitoring drives
![Test Image](test.PNG)
