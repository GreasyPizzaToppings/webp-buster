# webp-buster
Automatically replace incoming WebP files with PNG files continuously on specified paths or drives, with the option of converting all pre-existing webp's from a specified directory.

##  Usage
Usage: webp-buster.py [-h] [-d DEEP] [paths ...]

positional arguments:
  paths                 Paths to monitor (optional)

options:
  -h, --help            show this help message and exit
  -d DEEP, --deep DEEP  Directory to pre-convert WebP files


## Usage examples:
- `python webp-buster.py`
Monitor all drives for incoming WebP files
- `python webp-buster.py C:\\ D:\\`
Monitor C:\ and D:\ drives for incoming WebP files
- `python webp-buster.py C:\\Users\\PC\\Downloads\\`
Monitor Downloads folder for incoming WebP files
- `python webp-buster.py C:\\Users\\PC\\Downloads\\ C:\\Users\\PC\\Pictures`
Monitor Downloads folder and Pictures folder for incoming WebP files
- `python webp-buster.py --deep C:\\Users\\PC\\Downloads\\`
Replace existing WebP files in Downloads, then monitor all drives


## Logging:
Logs outputs to stdout (console) and to a file located at ~/WebP_Converter_Logs

## Example output:
![Test Image](test.PNG)
