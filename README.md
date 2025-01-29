# webp-buster
Automatically replace incoming WebP files with PNG files continuously on specified paths or drives, with the option of converting all pre-existing webp's from a specified directory.

##  Usage
`webp-buster.py [-h] [-f DIR] [paths ...]`

WebP to PNG Converter - Monitors directories and automatically converts WebP files to PNG format

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

## Logging:
Logs outputs to stdout (console) and to a file located at ~/WebP_Converter_Logs

## Example output of flushing a directory and then monitoring drives:
![Test Image](test.PNG)
