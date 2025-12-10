# Installation and Usage Guideline
## System Requirements
To avoid unexpected behavior, project should be run in Windows Subsytem for Linux (WSL). Other operating systems may work, but need to following installation of library-pyewf in troubleshooting section 
## Installation Steps
1. Clone folder `git clone https://github.com/TrimRio/CIS_542_Project` or Download Zip folder from this [repository](https://github.com/TrimRio/CIS_542_Project).  
2. Download the DiskImage folder from [here](https://umassd-my.sharepoint.com/:f:/r/personal/trioux_umassd_edu/Documents/Documents/CIS_542_ProjectShare?csf=1&web=1&e=ggK5tA) and place in the project folder that was cloned/downloaded from step 1.
3. Install library-pyewf in WSL
    5. `Sudo apt update`
    6. `Sudo apt install python3-libewf`
    7. check for installation with `python3 -c "import pyewf; print('pyewf loaded successfully')"`

## Usage Instructions
1. Open your preferred shell and launch WSL (e.g., by running wsl or opening your existing distribution such as Ubuntu). Then navigate to the CIS_542_Project directory.
2. It is recommended to begin with the deleted command `python3 main.py DiskImage/E01_v1.E01 deleted`, which will return the suspected deleted files and will print an example command of how to recover.
  3. Example deleted command `python3 main.py DiskImage/E01_v1.E01 deleted` 
4. To recover a deleted or hidden file, use the recover command with the following format `python3 main.py <img file path> recover <offset> <size in bytes>`
  1. Example recover command `python3 main.py DiskImage/E01_v1.E01 recover 9800 7338739 _ELETE~1.JPG`

## Troubleshooting
Ensure diskimage is located in folder and inside the project folder i.e., ~/CIS_542_Project/DiskImage/E01_v1.E01
