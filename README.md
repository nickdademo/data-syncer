data-syncer
===========
##Setup
### Windows
The following has been tested on:
 * Windows 8.1 Pro 64-bit  
 * Python 3.4.2 64-bit  
 * pysmb 1.1.14  
 * win_unc 0.6.1  
 * lxml 3.4.1  
 * psutil 2.2.1  
 * pywin32 Build 219  
 * cx_Freeze 4.3.4

#### Install Python:
1. Download the Python Windows installer from: https://www.python.org/downloads/  
2. During setup, ensure the *"Add python.exe to Path"* feature is installed.  
3. After installation, test that Python was properly added to the Windows Path by typing *python* into the Windows Command Prompt.  
4. If Python could not be found in the previous step. Do the following:  
i) In Windows, right-hand click "My Computer" or "This PC" and click Properties.  
ii) Click "Advanced system settings" and then "Environmental Variables".  
iii) Ensure that "C:\PythonXX\;C:\PythonXX\Scripts" is added to both the User Path and System Path variables (where XX is the Python version number).  
iv) Retry Step 3 in a new Command Prompt to verify the path has been setup correctly.  

#### Install pysmb:
1. In Command Prompt: *pip install pysmb*  

#### Install win_unc:
1. Clone repository: https://github.com/nickdademo/py_win_unc  
2. Checkout branch: *python3_port*  
3. Install via: *python setup.py install*  

#### Install lxml:
1. Download *lxml* from: http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml (choose file to match your Python version)  
2. Install lxml (requires _wheel_):  
*pip install wheel*  
*pip install downloaded_filename.whl*  

#### Install psutil:
1. In Command Prompt: *pip install psutil*  

#### Install Python For Windows Extensions (pywin32):
*Required for version information to be added to built EXE*  
1. Download installer for your Python version: http://sourceforge.net/projects/pywin32/  

##Usage

### data-syncer.py:
1. Open *data-syncer_config.xml* with your favourite text editor and set to suit your needs. 
2. Run script via Command Prompt:  
*python data-syncer.py -c* (where c = letter assigned to command)  
OR: *python data-syncer.py --long_command_name*  

##Creating a Standalone Windows Installer
1. Download *cx_Freeze* from: http://www.lfd.uci.edu/~gohlke/pythonlibs/#cx_freeze (choose file to match your Python version)  
2. Install cx_Freeze (requires _wheel_):  
*pip install wheel*  
*pip install downloaded_filename.whl*  
3. While in the directory containing the *data-syncer.py* script, run: *python setup.py bdist_msi*  
4. A Windows installer (e.g. *data-syncer-0.5.1-amd64.msi*) will be created in the _dist_ directory.
