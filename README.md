# Installation and Usage Guideline
## System Requirements
It is recommended to run this software tool in Windows Subsytem for Linux (WSL). Libewf library is required to use this software tool. Instructions for how to install this library are shown in the "Installation Steps" section. User of this tool with other operating systems may be more difficult to install the libewf library and may have unexpected behavior. 
## Installation Steps
1. Clone folder `git clone https://github.com/TrimRio/CIS_542_Project` or Download Zip folder from this [repository](https://github.com/TrimRio/CIS_542_Project).  
2. Download the DiskImage folder from [here](https://umassd-my.sharepoint.com/:f:/r/personal/trioux_umassd_edu/Documents/Documents/CIS_542_ProjectShare?csf=1&web=1&e=ggK5tA) and place in the project folder that was cloned/downloaded from step 1.
3. Install libewf in WSL
    1. `Sudo apt update`
    2. `Sudo apt install python3-libewf`
    3. check for installation with `python3 -c "import pyewf; print('pyewf loaded successfully')"`

## Usage Instructions
1. Open your preferred shell and launch WSL (e.g., by running wsl or opening your existing distribution such as Ubuntu). Then navigate to the CIS_542_Project directory.
2. It is recommended to begin with the deleted command `python3 main.py <image filepath> deleted`, which will return potential deleted files and will print an example command of how to recover.
    1. Example deleted command `python3 main.py DiskImage/E01_v1.E01 deleted`
3. To find files that were hidden by changing the extension, use the mismatch command `python3 main.py <image filepath> mismatch`
    1. Example mismatch command `python3 main.py DiskImage/E01_v1.E01 mismatch`     
4. To recover a deleted or hidden file, use the recover command with the following format `python3 main.py <image filepath> recover <offset> <size of file in bytes> <output filename>`. Recovered files will appear in the project folder with the output filename. If recovering from mismatch, use the expected/true extension with the output filename.
    1. Example recover command `python3 main.py DiskImage/E01_v1.E01 recover 9800 7338739 _ELETE~1.JPG`

## Troubleshooting
- Ensure diskimage is located in folder and inside the project folder i.e., ~/CIS_542_Project/DiskImage/E01_v1.E01
- See [here](https://github.com/libyal/libewf/wiki/Troubleshooting) for troubleshooting tips related to library-pyewf
