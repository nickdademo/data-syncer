Help / Version Information:
===========================
data-syncer -h / data-syncer --help

Return Codes:
=============
RETURN_EXIT__CLEAN_OP_SRC_EMPTY                             = 2
RETURN_EXIT__KEYBOARD_INT                                   = 1
RETURN_EXIT__SUCCESS                                        = 0
RETURN_EXIT__ERROR_INVALID_OPERATION                        = -1
RETURN_EXIT__ERROR_CONN_METHOD_PAIR_NOT_SUPPORTED           = -2
RETURN_EXIT__ERROR_INVALID_CONN_METHOD                      = -3
RETURN_EXIT__ERROR_OPERATION                                = -4
RETURN_EXIT__ERROR_VALIDATE_CONFIG_XML                      = -5
RETURN_EXIT__ERROR_CONFIG_NOT_FOUND_XML                     = -6
RETURN_EXIT__ERROR_CONFIG_NOT_FOUND_XSD                     = -7
RETURN_EXIT__ERROR_PARSE_CONFIG_XML                         = -8
RETURN_EXIT__ERROR_PARSE_CONFIG_XSD                         = -9
RETURN_EXIT__ERROR_CLEAN_OP_DST_DOES_NOT_CONTAIN_SRC        = -10
RETURN_EXIT__ERROR_CONN_METHOD_PAIR_HASHING_NOT_SUPPORTED   = -11
RETURN_EXIT__ERROR_FILE_HASH_MISMATCH                       = -12
RETURN_EXIT__ERROR_HELP_COMMAND_RESERVED                    = -13
RETURN_EXIT__ERROR_EXE_INSTANCES_LIMIT_EXCEEDED             = -14
RETURN_EXIT__ERROR_BACKUP_ARCHIVE_TEST_FAILED               = -15
RETURN_EXIT__ERROR_INVALID_LOGGING_MODE                     = -16
RETURN_EXIT__ERROR_LOGFILE_PERMISSION_DENIED                = -17
RETURN_EXIT__ERROR_LOGFILE_OPEN                             = -18
RETURN_EXIT__ERROR_INVALID_PATH                             = -19

Configuration
=============
loggingMode:            "OFF": Disables logging to files. "GLOBAL": A single log file is created containing all messages. "DUAL": In addition to a global log file, log messages are also separated into files which are suffixed with the long command name.
logFilePath:            Directory where log files will be created. If specified, path must end in a forward-slash or back-slash. If this field is left blank, log files will be created in the directory the tool is run from.

Folder
------
cmd:                    Single-letter (e.g. "a") assigned to command to be used when running tool: e.g. data-syncer -a
                        NOTE: "h" cannot be used as it is reserved for the Help command.
cmd_long:               Descriptive command name to be used when running tool: e.g. data-syncer --longer_command_name
                        NOTE: "help" cannot be used as it is reserved for the Help command.
desc:                   Optional command description to be displayed when the tool is run with: -h/--help
maxRetries:             Number of times to retry the command before the tool exits.
retryInterval:          This specifies the time in seconds between retry attempts (time is measured from completion of command).
operation:              Type of operation to perform:
                        "SYNC": Make DST same as SRC - i.e. DST will be changed to match SRC.
                        "COPY": Copy contents of SRC to DST. If file exists in DST (at the same path), it will be overwritten if it has a different SIZE or LAST MODIFIED.
                        "MOVE": Move contents of SRC to DST. If file exists in DST (at the same path), it will be overwritten if it has a different SIZE or LAST MODIFIED.
                        "CLEAN": Delete contents of SRC if DST contains all files/folders in SRC.
                        "CLEAN_DEL": Same as the "CLEAN" operation except that the SRC directory is deleted at the end of the operation.
doHashCheck:            Set to "true" to enable SHA256 file hash checks to validate file copy operations in SYNC, COPY and MOVE. For the CLEAN operation, SRC contents will be validated against DST before deleting.
                        Set to "false" to disable.
                        NOTE: This feature is currently only available for LOCAL->LOCAL, LOCAL->UNC, UNC->LOCAL, UNC->UNC operations.
nAllowedEXEInstances:   Set to "1" to allow only ONE instance of the executable to run at once. With this feature, the tool will return an exit code if the number of currently running processes exceeds the limit set.

Source/Destination
------------------
connectionMethod:   Connection method to use to access path.
                    "LOCAL": Path is a local path or UNC path not requiring authentication.
                    "UNC": Path is a UNC path. Authentication is used if supplied.
                    "SMB": Path is a remote location to be accessed via SMB/CIFS.
                    NOTE: SMB->SMB operation is not supported.
path:               Path to target folder. The format of this attribute depends on the value of connectionMethod.
                    For LOCAL: C:/path/to/folder/ or \\server\share\path\to\folder\
                    For UNC: \\server\share\path\to\folder\
                    For SMB: /path/to/folder/
                    NOTE: On Windows, %name% expansions of environmental variables are supported in addition to $name and ${name}.
pathFilter:         Allows the tool to perform the command only on FOLDER paths which match a REGULAR EXPRESSION. The matching begins at the START of the path string.
                    NOTE: '//' corresponds to the root/top-level directory.
                    For example:
                        pathFilter="['.*']"                                 : All folder paths under "path" will be included.
                        pathFilter="['//$']"                                : Only "path" will be included (i.e. sub-directories under the top-level will NOT be included). '$' denotes the end of path string.
                        pathFilter="['//FolderNameA/$']"                    : Only //FolderNameA/ path will be included. Path name must end with a forward-slash in order not to also match 'FolderNameAX'.
                        pathFilter="['.*/FolderNameA/']"                    : Paths which contain the folder 'FolderNameA' at any level will be included.
                        pathFilter="['//FolderName']"                       : Paths such as //FolderName/, //FolderNameA/, //FolderNameB/C/D/ etc. will be included.
                        pathFilter="['//FolderName/']"                      : Paths such as //FolderName/ and any subdirectories such as //FolderName/A/B/ etc. will be included.
                        pathFilter="['//FolderNameA/','//FolderNameB/']"    : Paths such as //FolderNameA/, //FolderNameA/C/, //FolderNameB/, //FolderNameB/D/ will be included.
fileFilter:         Allows the tool to perform the command only on FILES which match a REGULAR EXPRESSION. The matching begins at the START of the filename string.
                    For example:
                        fileFilter="['.*']"                                 : All files under "path" will be included.
                        fileFilter="['.*.xml']"                             : Only include .xml files.
                        fileFilter="['SomeText.*.xml']"                     : Only include .xml files which begin with "SomeText".
                        fileFilter="['.*.xml','.*.xsd']"                    : Only include .xml and .xsd files.

BackupArchive
-------------
enable:             Enable the creation of a backup archive before any changes occur to folder. Set to either "true" or "false".
filenamePrefix:     Specify the archive filename prefix. Tool will prepend '.' to the supplied prefix: .filenamePrefix-YYYYmmddHHMMSS
storeRootFolder:    Store the root (i.e. top-level) folder in the backup archive. Set to either "true" or "false".
test:               Set to "true" to test the backup archive after creation. Otherwise set to "false". If set, tool will exit immediately and return an appropriate error code if archive test fails.

SMB
---
username:           Username required to authenticate the underlying SMB connection with the remote server.
password:           Password required to authenticate the underlying SMB connection with the remote server.
serverName:         The NetBIOS machine name of the remote server. On Windows, you can find out the machine name by right-clicking on the "My Computer" and selecting "Properties".
ipAddress:          IP address of remote server.
port:               The default TCP port for most SMB/CIFS servers using NetBIOS over TCP/IP is 139.
                    Some newer server installations might also support Direct hosting of SMB over TCP/IP; for these servers, the default TCP port is 445.
clientName:         The local NetBIOS machine name that will identify where this connection is originating from.
shareName:          Share name references a label created by an administrator or, in some cases, within the operating system. In a UNC path: \\server\sharename\path\to\folder

UNC
---
username:           Username required to access path. Typically in the form "ComputerName\Username".
password:           Password required to access path..