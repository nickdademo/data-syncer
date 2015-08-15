from smb.SMBConnection import *
from smb.base import SharedFile
import datetime
import os
import argparse
from collections import defaultdict
import zipfile
import shutil
import tempfile
from lxml import etree
import time
import fnmatch
import re
import hashlib
import base64
import psutil
import logging
import stat
# win_unc is only for Windows
if sys.platform == 'win32':
    from win_unc import (DiskDrive, UncDirectory, UncDirectoryConnection, UncDirectoryMount, UncCredentials)

VERSION_STR                     = '0.5.1'
TIMESTAMP_FORMAT_STR            = '%Y%m%d%H%M%S'
CONFIG_FILENAME_XML             = 'data-syncer_config.xml'
CONFIG_FILENAME_XSD             = 'data-syncer_config.xsd'
BOOLEAN_TRUE_STR                = 'true'
CONN_METHOD_STR_LOCAL           = "LOCAL"
CONN_METHOD_STR_SMB             = "SMB"
CONN_METHOD_STR_UNC             = "UNC"
OPERATION_METHOD_STR_COPY       = 'COPY'
OPERATION_METHOD_STR_MOVE       = 'MOVE'
OPERATION_METHOD_STR_SYNC       = 'SYNC'
OPERATION_METHOD_STR_CLEAN      = 'CLEAN'
OPERATION_METHOD_STR_CLEAN_DEL  = 'CLEAN_DEL'
LOGGING_MODE_STR_OFF            = 'OFF'
LOGGING_MODE_STR_GLOBAL         = 'GLOBAL'
LOGGING_MODE_STR_DUAL           = 'DUAL'
BACKUP_ARCHIVE_FILENAME_PREFIX  = '.'
EXE_FILENAME                    = 'data-syncer.exe'
LOG_LEVEL                       = 'DEBUG'
LOG_FORMAT                      = '%(asctime)s - %(levelname)s - %(message)s'
LOG_FILENAME                    = 'data-syncer_LOG'
LOG_FILENAME_EXT                = '.txt'

operationStrs                   = [OPERATION_METHOD_STR_COPY, OPERATION_METHOD_STR_MOVE, OPERATION_METHOD_STR_SYNC, OPERATION_METHOD_STR_CLEAN, OPERATION_METHOD_STR_CLEAN_DEL]
connMethodStrs                  = [CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_SMB, CONN_METHOD_STR_UNC]
loggingModeStrs                 = [LOGGING_MODE_STR_OFF, LOGGING_MODE_STR_GLOBAL, LOGGING_MODE_STR_DUAL]

# Valid connection method pairs
# "UNC" connection method is only available in Windows
if sys.platform == 'win32':
    validConnMethodPairs    = [
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_LOCAL),
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_UNC),
        (CONN_METHOD_STR_UNC, CONN_METHOD_STR_LOCAL),
        (CONN_METHOD_STR_UNC, CONN_METHOD_STR_UNC),
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_SMB),
        (CONN_METHOD_STR_SMB, CONN_METHOD_STR_LOCAL),
        (CONN_METHOD_STR_UNC, CONN_METHOD_STR_SMB),
        (CONN_METHOD_STR_SMB, CONN_METHOD_STR_UNC)
    ]
else:
    validConnMethodPairs    = [
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_LOCAL),
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_SMB),
        (CONN_METHOD_STR_SMB, CONN_METHOD_STR_LOCAL),
    ]

# Valid connection method pairs for file hash checking
# "UNC" connection method is only available in Windows
if sys.platform == 'win32':
    validHashCheckConnMethods    = [
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_LOCAL),
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_UNC),
        (CONN_METHOD_STR_UNC, CONN_METHOD_STR_LOCAL),
        (CONN_METHOD_STR_UNC, CONN_METHOD_STR_UNC)
    ]
else:
    validHashCheckConnMethods   = [
        (CONN_METHOD_STR_LOCAL, CONN_METHOD_STR_LOCAL)
    ]

# Return codes
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

# Function which allow deleting of read-only files/dirs with shutil.rmtree
def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

#######################################################################################
#                                 WRAPPER FUNCTIONS                                   #
#######################################################################################

def _getDict(conn, pathFilter, fileFilter):
    connMethod = conn.xpath('@connectionMethod')[0]
    path = os.path.expandvars(conn.xpath('@path')[0])
    if connMethod == CONN_METHOD_STR_LOCAL:
        return getDict_Local(path, pathFilter, fileFilter)
    elif connMethod == CONN_METHOD_STR_UNC:
        # Use credentials if provided
        username = conn.xpath('UNC/@username')[0]
        password = conn.xpath('UNC/@password')[0]
        if username != '':
            creds = UncCredentials(username, password)
        else:
            creds = None
        # Connect
        with UncDirectoryConnection(UncDirectory(path, creds)) as conn:
            # Get dict
            d = getDict_Local(path, pathFilter, fileFilter)
        return d
    elif connMethod == CONN_METHOD_STR_SMB:
        # Connect to remote machine
        username = conn.xpath('SMB/@username')[0]
        password = conn.xpath('SMB/@password')[0]
        clientName = conn.xpath('SMB/@clientName')[0]
        serverName = conn.xpath('SMB/@serverName')[0]
        ipAddress = conn.xpath('SMB/@ipAddress')[0]
        port = conn.xpath('SMB/@port')[0]
        shareName = conn.xpath('SMB/@shareName')[0]
        smbConn = SMBConnection(username, password, clientName, serverName, use_ntlm_v2 = True)
        ret = smbConn.connect(ipAddress, int(port));
        # Get dict
        d = getDict_Remote(smbConn, shareName, path, pathFilter, fileFilter)
        # Disconnect
        smbConn.close()
        return d

def _doBackup(conn, backupArchiveFilenamePrefix, timestamp, storeRootFolderInBackupArchive, testBackupArchive):
    connMethod = conn.xpath('@connectionMethod')[0]
    path = os.path.expandvars(conn.xpath('@path')[0])
    if connMethod == CONN_METHOD_STR_LOCAL:
        doBackup_Local(path, backupArchiveFilenamePrefix, timestamp, storeRootFolderInBackupArchive, testBackupArchive)
    elif connMethod == CONN_METHOD_STR_UNC:
        # Use credentials if provided
        username = conn.xpath('UNC/@username')[0]
        password = conn.xpath('UNC/@password')[0]
        if username != '':
            creds = UncCredentials(username, password)
        else:
            creds = None
        # Connect
        with UncDirectoryConnection(UncDirectory(path, creds)) as conn:
            # Do backup
            doBackup_Local(path, backupArchiveFilenamePrefix, timestamp, storeRootFolderInBackupArchive, testBackupArchive)
    elif connMethod == CONN_METHOD_STR_SMB:
        # Connect to remote machine
        username = conn.xpath('SMB/@username')[0]
        password = conn.xpath('SMB/@password')[0]
        clientName = conn.xpath('SMB/@clientName')[0]
        serverName = conn.xpath('SMB/@serverName')[0]
        ipAddress = conn.xpath('SMB/@ipAddress')[0]
        port = conn.xpath('SMB/@port')[0]
        shareName = conn.xpath('SMB/@shareName')[0]
        smbConn = SMBConnection(username, password, clientName, serverName, use_ntlm_v2 = True)
        ret = smbConn.connect(ipAddress, int(port));
        # Do backup
        pathFilter = eval(conn.xpath('@pathFilter')[0])
        fileFilter = eval(conn.xpath('@fileFilter')[0])
        doBackup_Remote(smbConn, shareName, path, backupArchiveFilenamePrefix, timestamp, storeRootFolderInBackupArchive, testBackupArchive, pathFilter, fileFilter)
        # Disconnect
        smbConn.close()

def _doDelete(conn, left, right, backupArchiveFilenamePrefix):
    connMethod = conn.xpath('@connectionMethod')[0]
    path = os.path.expandvars(conn.xpath('@path')[0])
    if connMethod == CONN_METHOD_STR_LOCAL:
        doDelete_Local(left, right, path, backupArchiveFilenamePrefix)
    elif connMethod == CONN_METHOD_STR_UNC:
        # Use credentials if provided
        username = conn.xpath('UNC/@username')[0]
        password = conn.xpath('UNC/@password')[0]
        if username != '':
            creds = UncCredentials(username, password)
        else:
            creds = None
        # Connect
        with UncDirectoryConnection(UncDirectory(path, creds)) as conn:
            # Do delete
            doDelete_Local(left, right, path, backupArchiveFilenamePrefix)
    elif connMethod == CONN_METHOD_STR_SMB:
        # Connect to remote machine
        username = conn.xpath('SMB/@username')[0]
        password = conn.xpath('SMB/@password')[0]
        clientName = conn.xpath('SMB/@clientName')[0]
        serverName = conn.xpath('SMB/@serverName')[0]
        ipAddress = conn.xpath('SMB/@ipAddress')[0]
        port = conn.xpath('SMB/@port')[0]
        shareName = conn.xpath('SMB/@shareName')[0]
        smbConn = SMBConnection(username, password, clientName, serverName, use_ntlm_v2 = True)
        ret = smbConn.connect(ipAddress, int(port));
        # Do delete
        doDelete_Remote(smbConn, shareName, left, right, path, backupArchiveFilenamePrefix)
        # Disconnect
        smbConn.close()

def _copy(connSrc, connDst, diffListSrc, doHashCheck):
    srcConnMethod = connSrc.xpath('@connectionMethod')[0]
    dstConnMethod = connDst.xpath('@connectionMethod')[0]
    srcPath = os.path.expandvars(connSrc.xpath('@path')[0])
    dstPath = os.path.expandvars(connDst.xpath('@path')[0])
    # LOCAL->LOCAL copy
    if srcConnMethod == CONN_METHOD_STR_LOCAL and dstConnMethod == CONN_METHOD_STR_LOCAL:
        return copy_Local(diffListSrc, srcPath, dstPath, doHashCheck)
    # LOCAL->UNC copy
    elif srcConnMethod == CONN_METHOD_STR_LOCAL and dstConnMethod == CONN_METHOD_STR_UNC:
        # Use credentials if provided
        username = connDst.xpath('UNC/@username')[0]
        password = connDst.xpath('UNC/@password')[0]
        if username != '':
            creds = UncCredentials(username, password)
        else:
            creds = None
        # Connect
        with UncDirectoryConnection(UncDirectory(dstPath, creds)) as conn:
            # Do copy
            n = copy_Local(diffListSrc, srcPath, dstPath, doHashCheck)
        return n
    # UNC->LOCAL copy
    elif srcConnMethod == CONN_METHOD_STR_UNC and dstConnMethod == CONN_METHOD_STR_LOCAL:
        # Use credentials if provided
        username = connSrc.xpath('UNC/@username')[0]
        password = connSrc.xpath('UNC/@password')[0]
        if username != '':
            creds = UncCredentials(username, password)
        else:
            creds = None
        # Connect
        with UncDirectoryConnection(UncDirectory(srcPath, creds)) as conn:
            # Do copy
            n = copy_Local(diffListSrc, srcPath, dstPath, doHashCheck)
        return n
    # UNC->UNC copy
    elif srcConnMethod == CONN_METHOD_STR_UNC and dstConnMethod == CONN_METHOD_STR_UNC:
        # SRC
        # Use credentials if provided
        username1 = connSrc.xpath('UNC/@username')[0]
        password1 = connSrc.xpath('UNC/@password')[0]
        if username1 != '':
            creds1 = UncCredentials(username1, password1)
        else:
            creds1 = None
        # Connect
        with UncDirectoryConnection(UncDirectory(srcPath, creds1)) as conn1:
            # DST
            # Use credentials if provided
            username2 = connDst.xpath('UNC/@username')[0]
            password2 = connDst.xpath('UNC/@password')[0]
            if username2 != '':
                creds2 = UncCredentials(username2, password2)
            else:
                creds2 = None
            # Connect
            with UncDirectoryConnection(UncDirectory(dstPath, creds2)) as conn2:
                # Do copy
                n = copy_Local(diffListSrc, srcPath, dstPath, doHashCheck)
        return n
    # LOCAL->SMB copy
    elif srcConnMethod == CONN_METHOD_STR_LOCAL and dstConnMethod == CONN_METHOD_STR_SMB:
        # Connect to remote machine
        username = connDst.xpath('SMB/@username')[0]
        password = connDst.xpath('SMB/@password')[0]
        clientName = connDst.xpath('SMB/@clientName')[0]
        serverName = connDst.xpath('SMB/@serverName')[0]
        ipAddress = connDst.xpath('SMB/@ipAddress')[0]
        port = connDst.xpath('SMB/@port')[0]
        shareName = connDst.xpath('SMB/@shareName')[0]
        smbConn = SMBConnection(username, password, clientName, serverName, use_ntlm_v2 = True)
        ret = smbConn.connect(ipAddress, int(port));
        # Do copy (upload)
        n = copyTo_Remote(smbConn, shareName, diffListSrc, dstPath, srcPath)
        # Disconnect
        smbConn.close()
        return n
    # SMB->LOCAL copy
    elif srcConnMethod == CONN_METHOD_STR_SMB and dstConnMethod == CONN_METHOD_STR_LOCAL:
        # Connect to remote machine
        username = connSrc.xpath('SMB/@username')[0]
        password = connSrc.xpath('SMB/@password')[0]
        clientName = connSrc.xpath('SMB/@clientName')[0]
        serverName = connSrc.xpath('SMB/@serverName')[0]
        ipAddress = connSrc.xpath('SMB/@ipAddress')[0]
        port = connSrc.xpath('SMB/@port')[0]
        shareName = connSrc.xpath('SMB/@shareName')[0]
        smbConn = SMBConnection(username, password, clientName, serverName, use_ntlm_v2 = True)
        ret = smbConn.connect(ipAddress, int(port));
        # Do copy (download)
        n = copyFrom_Remote(smbConn, shareName, diffListSrc, srcPath, dstPath)
        # Disconnect
        smbConn.close()
        return n
    # UNC->SMB copy
    elif srcConnMethod == CONN_METHOD_STR_UNC and dstConnMethod == CONN_METHOD_STR_SMB:
        # Use credentials if provided
        usernameUNC = connSrc.xpath('UNC/@username')[0]
        passwordUNC = connSrc.xpath('UNC/@password')[0]
        if usernameUNC != '':
            creds = UncCredentials(usernameUNC, passwordUNC)
        else:
            creds = None
        # Connect
        with UncDirectoryConnection(UncDirectory(srcPath, creds)) as conn:
            # Connect to remote machine
            username = connDst.xpath('SMB/@username')[0]
            password = connDst.xpath('SMB/@password')[0]
            clientName = connDst.xpath('SMB/@clientName')[0]
            serverName = connDst.xpath('SMB/@serverName')[0]
            ipAddress = connDst.xpath('SMB/@ipAddress')[0]
            port = connDst.xpath('SMB/@port')[0]
            shareName = connDst.xpath('SMB/@shareName')[0]
            smbConn = SMBConnection(username, password, clientName, serverName, use_ntlm_v2 = True)
            ret = smbConn.connect(ipAddress, int(port));
            # Do copy (upload)
            n = copyTo_Remote(smbConn, shareName, diffListSrc, dstPath, srcPath)
            # Disconnect
            smbConn.close()
        return n
    # SMB->UNC copy
    elif srcConnMethod == CONN_METHOD_STR_SMB and dstConnMethod == CONN_METHOD_STR_UNC:
        # Use credentials if provided
        usernameUNC = connDst.xpath('UNC/@username')[0]
        passwordUNC = connDst.xpath('UNC/@password')[0]
        if usernameUNC != '':
            creds = UncCredentials(usernameUNC, passwordUNC)
        else:
            creds = None
        # Connect
        with UncDirectoryConnection(UncDirectory(dstPath, creds)) as conn:
            # Connect to remote machine
            username = connSrc.xpath('SMB/@username')[0]
            password = connSrc.xpath('SMB/@password')[0]
            clientName = connSrc.xpath('SMB/@clientName')[0]
            serverName = connSrc.xpath('SMB/@serverName')[0]
            ipAddress = connSrc.xpath('SMB/@ipAddress')[0]
            port = connSrc.xpath('SMB/@port')[0]
            shareName = connSrc.xpath('SMB/@shareName')[0]
            smbConn = SMBConnection(username, password, clientName, serverName, use_ntlm_v2 = True)
            ret = smbConn.connect(ipAddress, int(port));
            # Do copy (download)
            n = copyFrom_Remote(smbConn, shareName, diffListSrc, srcPath, dstPath)
            # Disconnect
            smbConn.close()
        return n

#######################################################################################
#                                 COMMON FUNCTIONS                                    #
#######################################################################################

def zipDir(inputDir, outputZip, backupArchiveFilenamePrefix, includeDirInZip=True, testZip=True):
    # Create archive
    with zipfile.ZipFile(outputZip, 'w', compression=zipfile.ZIP_DEFLATED) as zipOut:
        rootLen = len(os.path.dirname(inputDir))
        parentDir, dirToZip = os.path.split(inputDir)
        def trimPath(path):
            archivePath = path
            if not includeDirInZip:
                archivePath = archivePath.replace(dirToZip + '/', "", 1)
            return archivePath
        def _ArchiveDirectory(parentDirectory):
            contents = os.listdir(parentDirectory)
            # Store empty directory
            if not contents:
                # http://www.velocityreviews.com/forums/t318840-add-empty-directory-using-zipfile.html
                archiveRoot = parentDirectory[rootLen:].replace('\\', '/').lstrip('/')
                zipInfo = zipfile.ZipInfo(trimPath(archiveRoot) + '/')
                zipOut.writestr(zipInfo, '')
            # File
            for item in contents:
                if not item.startswith(backupArchiveFilenamePrefix):
                    fullPath = os.path.join(parentDirectory, item)
                    if os.path.isdir(fullPath) and not os.path.islink(fullPath):
                        _ArchiveDirectory(fullPath)
                    else:
                        archiveRoot = fullPath[rootLen:].replace('\\', '/').lstrip('/')
                        zipOut.write(fullPath, trimPath(archiveRoot), zipfile.ZIP_DEFLATED)
        _ArchiveDirectory(inputDir)
    # Test archive
    if testZip:
        with zipfile.ZipFile(outputZip, 'r') as zipOut:
            testRet = zipOut.testzip()
            if testRet:
                logger.error("BACKUP_ARCHIVE_TEST_FAILED: Backup archive test failed: %s" % outputZip)
                logger.error("Failed: %s" % testRet)
                logger.error('Program will now exit.')
                zipOut.close()
                sys.exit(RETURN_EXIT__ERROR_BACKUP_ARCHIVE_TEST_FAILED)
            else:
                logger.info("Backup archive test passed: %s" % outputZip)

def getSharedFileObject(fileList, filename):
    for file in fileList:
        if file.filename == filename:
            return file;
    return None

def doComparison(left, right):
    n = 0
    # This returns a list of files which are new or modified in LEFT
    diffList = defaultdict(list)
    for (path, fileList) in left.items():
        for file in fileList:
            # Firstly, check if path exists in RIGHT
            if path in right:
                # Next, check if file exists in RIGHT
                f = getSharedFileObject(right[path], file.filename)
            else:
                f = None
            # File with same filename DOES NOT exist in RIGHT
            if f == None:
                # Add to diff list
                diffList[path].append(file);
                n += 1
                logger.info("NEW FILE in Left: %s" % (path + file.filename))
            # File with same filename exists in RIGHT
            else:
                # Skip if "files" are NOT of the same type (i.e. both files or both directories)
                if f.isDirectory != file.isDirectory:
                    continue
                # Do further comparisons (only if NOT a directory)
                if not f.isDirectory:
                    # SIZE
                    if f.file_size != file.file_size:
                        diffList[path].append(file);
                        n += 1
                        logger.info("SIZE MISMATCH (%s): Left=%s Right=%s" % ((path + file.filename), file.file_size, f.file_size))
                        continue
                    # LAST MODIFIED
                    if f.last_write_time != file.last_write_time:
                        diffList[path].append(file);
                        n += 1
                        logger.info("LAST MODIFIED MISMATCH (%s): Left=%f Right=%f" % ((path + file.filename), file.last_write_time, f.last_write_time))
                        continue
    return diffList, n

def getHash(file_name):
    with open(file_name, 'rb') as f:
        m = hashlib.sha256()
        m.update(f.read())
        sha = m.digest()
        res = base64.b64encode(sha)
    return res

#######################################################################################
#                                   LOCAL FUNCTIONS                                   #
#######################################################################################

def populateDict_Local(local, localPath, path, pathFilter, fileFilter):
    for filename in os.listdir(localPath + path):
        # Ignore files/folders starting with '.'
        if not filename.startswith('.'):
            # Add forward slash to end of filename if directory
            # Create variable to be used in path filter
            _path = '//'
            if os.path.isdir(localPath + path + filename):
                filename += '/'
                _path += path + filename
            else:
                _path += path
            filePath = localPath + path + filename
            # Create SharedFile object
            size = os.stat(filePath).st_size
            last_write_time = os.stat(filePath).st_mtime_ns
            last_access_time = os.stat(filePath).st_atime
            create_time = os.stat(filePath).st_ctime
            # DIRECTORY
            if os.path.isdir(filePath):
                # Create file object
                file = SharedFile(create_time, last_access_time, last_write_time, None, size, None, SMB_FILE_ATTRIBUTE_DIRECTORY, None, filename)
                # Check folder filter
                if any(re.match(p, _path) for p in pathFilter):
                    # Add to dict
                    local[path].append(file)
                # Enter directory
                populateDict_Local(local, localPath, path + file.filename, pathFilter, fileFilter)
            # FILE
            else:
                # Check BOTH file and folder filters
                if any(re.match(f, filename) for f in fileFilter) and any(re.match(p, _path) for p in pathFilter):
                    # Create file object
                    file = SharedFile(create_time, last_access_time, last_write_time, None, size, None, SMB_FILE_ATTRIBUTE_NORMAL, None, filename)
                    # Add to dict
                    local[path].append(file)
                
def getDict_Local(localPath, pathFilter, fileFilter):
    local = defaultdict(list)
    populateDict_Local(local, localPath, '', pathFilter, fileFilter)
    return local

def doBackup_Local(localPath, backupArchiveFilenamePrefix, timestamp, storeRootFolderInBackupArchive, testBackupArchive):
    logger.info('Creating local backup archive...')
    zipFilePath = localPath + backupArchiveFilenamePrefix + '-' + timestamp.strftime(TIMESTAMP_FORMAT_STR) + '.zip'
    zipDir(os.path.dirname(localPath), zipFilePath, backupArchiveFilenamePrefix, storeRootFolderInBackupArchive, testBackupArchive)
    logger.info("Local backup archive created: %s" % zipFilePath)

def doDelete_Local(left, right, localPath, backupArchiveFilenamePrefix):
    # LEFT = Files/folders that delete operation will occur on
    for (path, fileList) in left.items():
        for file in fileList:
            # Check if file exists in RIGHT
            if path in right:
                f = getSharedFileObject(right[path], file.filename)
            else:
                f = None
            # File with same filename DOES NOT exist in RIGHT
            if f == None and not file.filename.startswith(backupArchiveFilenamePrefix):
                if os.path.exists(localPath + path + file.filename):
                    if file.isDirectory:
                        shutil.rmtree(localPath + path + file.filename, onerror=remove_readonly)
                        logger.info('Deleted local directory: %s' % (localPath + path + file.filename))
                    else:
                        os.remove(localPath + path + file.filename)
                        logger.info('Deleted local file: %s' % (localPath + path + file.filename))
                else:
                    logger.warning('Local path does not exist (already deleted): %s' % (localPath + path + file.filename))

def copy_Local(copyList, srcPath, dstPath, doHashCheck):
    n = 0
    # Create DST directory structure first
    for (path, fileList) in copyList.items():
        for file in (f for f in fileList if f.isDirectory):
            filename = file.filename
            if not os.path.exists(dstPath + path + filename):
                os.makedirs(dstPath + path + filename)
                logger.info("Local path created: %s"  % (dstPath + path + filename))
            else:
                logger.info("Local path already exists: %s"  % (dstPath + path + filename))
            # Set Last Modified and Last Accessed times to match SRC
            os.utime(dstPath + path + filename, None, ns=(file.last_access_time, file.last_write_time))
            n += 1
    # Copy file(s)
    for (path, fileList) in copyList.items():
        for file in (f for f in fileList if not f.isDirectory):
            filename = file.filename
            # Do copy
            shutil.copy(srcPath + path + filename, dstPath + path + filename)
            # Check if hashes match
            if doHashCheck:
                srcFile_sha = getHash(srcPath + path + filename)
                dstFile_sha = getHash(dstPath + path + filename)
                if srcFile_sha != dstFile_sha:
                    # Delete copied file (undo copy operation)
                    os.remove(dstPath + path + filename)
                    logger.info('Deleted copied file: %s' % (dstPath + path + filename))
                    raise Exception("File hashes do not match: SRC(%s)=%s, DST(%s)=%s" % (srcPath + path + filename, srcFile_sha, dstPath + path + filename, dstFile_sha))
            logger.info("Local copy complete: %s -> %s" % ((srcPath + path + filename),(dstPath + path + filename)))
            # Set Last Modified and Last Accessed times to match remote machine
            os.utime(dstPath + path + filename, None, ns=(file.last_access_time, file.last_write_time))
            n += 1
    # Ensure attributes of DST folders match SRC folders
    # NOTE: This is required because adding a file into a folder changes its attributes
    for (path, fileList) in copyList.items():
        for file in (f for f in fileList if f.isDirectory):
            filename = file.filename
            # Set Last Modified and Last Accessed times to match SRC
            os.utime(dstPath + path + filename, None, ns=(file.last_access_time, file.last_write_time))
    return n

#######################################################################################
#                                   REMOTE FUNCTIONS                                  #
#######################################################################################

def populateDict_Remote(conn, remote, shareName, remotePath, path, pathFilter, fileFilter):
    for file in conn.listPath(shareName, remotePath + path):
        # Ignore files/folders starting with '.'
        if not file.filename.startswith('.'):
            # Add forward slash to end of filename if directory
            # Create variable to be used in path filter
            _path = '//'
            if file.isDirectory:
                file.filename += '/'
                _path += path + file.filename
            else:
                _path += path
            # DIRECTORY
            if file.isDirectory:
                # Check folder filter
                if any(re.match(p, _path) for p in pathFilter):
                    # Add to dict
                    remote[path].append(file)
                # Enter directory
                populateDict_Remote(conn, remote, shareName, remotePath, path + file.filename, pathFilter, fileFilter)
            # FILE
            else:
                # Check BOTH file and folder filters
                if any(re.match(f, file.filename) for f in fileFilter) and any(re.match(p, _path) for p in pathFilter):
                    # Add to dict
                    remote[path].append(file)

def getDict_Remote(conn, shareName, remotePath, pathFilter, fileFilter):
    remote = defaultdict(list)
    populateDict_Remote(conn, remote, shareName, remotePath, '', pathFilter, fileFilter)
    return remote

def doBackup_Remote(conn, shareName, remotePath, backupArchiveFilenamePrefix, timestamp, storeRootFolderInBackupArchive, testBackupArchive, pathFilter, fileFilter):
    logger.info('Creating remote backup archive...')
    # Get remote contents
    remote = getDict_Remote(conn, shareName, remotePath, pathFilter, fileFilter)
    # Create temporary download directory on local
    with tempfile.TemporaryDirectory() as temp_dir:
        # Download all files in remote
        copyFrom_Remote(conn, shareName, remote, remotePath, temp_dir + '/')
        # Create temporary local ZIP
        zipFilename =  backupArchiveFilenamePrefix + '-' + timestamp.strftime(TIMESTAMP_FORMAT_STR) + '.zip'
        zipFilePath = temp_dir + '/' + zipFilename
        zipDir(temp_dir, zipFilePath, backupArchiveFilenamePrefix, storeRootFolderInBackupArchive, testBackupArchive)
        logger.info("Remote backup archive created: %s" % zipFilePath)
        # Upload ZIP to remote
        with open(zipFilePath, "rb") as f:
            logger.info("Uploading backup archive: %s"  % zipFilePath)
            file_size = conn.storeFile(shareName, remotePath + zipFilename, f)
            logger.info("Upload complete [%s bytes(s)]: %s" % (file_size, (remotePath + zipFilename)))
            f.close()

def doDelete_Remote(conn, shareName, left, right, remotePath, backupArchiveFilenamePrefix):
    # LEFT = Files/folders that delete operation will occur on
    deferDelete = defaultdict(list)
    for (path, fileList) in left.items():
        for file in fileList:
            # Check if file exists in RIGHT
            if path in right:
                f = getSharedFileObject(right[path], file.filename)
            else:
                f = None
            # File with same filename DOES NOT exist in RIGHT
            if f == None and not file.filename.startswith(backupArchiveFilenamePrefix):
                if file.isDirectory:
                    # Check if directory is empty
                    if isRemoteDirEmpty(conn, shareName, remotePath + path + file.filename):
                        # This command is only able to delete an EMPTY directory
                        conn.deleteDirectory(shareName, remotePath + path + file.filename)
                        logger.info('Deleted remote directory: %s' % (remotePath + path + file.filename))
                    else:
                        deferDelete[path].append(file)
                        logger.warning('Cannot delete remote path (not empty). Deletion will be deferred: %s' % (remotePath + path + file.filename))
                else:
                    conn.deleteFiles(shareName, remotePath + path + file.filename)
                    logger.info('Deleted remote file: %s' % (remotePath + path + file.filename))
    # Perform deferred deletions
    if len(deferDelete) > 0:
        doDelete_Remote(conn, shareName, deferDelete, right, remotePath, backupArchiveFilenamePrefix)  

def isDirEmpty_Remote(conn, shareName, path):
    list = conn.listPath(shareName, path)
    for l in list:
        if not l.filename.startswith('.'):
            return False
    return True

def doesDirExist_Remote(conn, shareName, path):
    try:
        conn.listPath(shareName, path)
        return True
    except Exception:
        return False

def createPath_Remote(conn, shareName, path):
    if not doesDirExist_Remote(conn, shareName, path):
        logger.info('Creating directory: %s'  % path)
        conn.createDirectory(shareName, path)
        logger.info('Directory created: %s'  % (shareName + path))

def copyFrom_Remote(conn, shareName, downloadList, remotePath, localPath):
    n = 0
    # Create local directory structure first
    for (path, fileList) in downloadList.items():
        for file in (f for f in fileList if f.isDirectory):
            filename = file.filename
            if not os.path.exists(localPath + path + filename):
                os.makedirs(localPath + path + filename)
                logger.info("Path created: %s"  % (localPath + path + filename))
            else:
                logger.info("Path already exists: %s"  % (localPath + path + filename))
            # Set Last Modified and Last Accessed times to match remote machine
            os.utime(localPath + path + filename, None, ns=(file.last_access_time, file.last_write_time))
            n += 1
    # Download file(s)
    for (path, fileList) in downloadList.items():
        for file in (f for f in fileList if not f.isDirectory):
            filename = file.filename
            with open(localPath + path + filename, "wb") as f:
                logger.info("Downloading remote file: %s"  % (shareName + remotePath + path + filename))
                file_attrs, file_size = conn.retrieveFile(shareName, remotePath + path + filename, f)
                logger.info("Download complete [%d byte(s)]: %s" % (file_size, (localPath + path + filename)))
                f.close()
            # Set Last Modified and Last Accessed times to match remote machine
            os.utime(localPath + path + filename, None, ns=(file.last_access_time, file.last_write_time))
            n += 1
    # Ensure attributes of local folders match remote
    # NOTE: This is required because downloading a file into a folder changes its attributes
    for (path, fileList) in downloadList.items():
        for file in (f for f in fileList if f.isDirectory):
            filename = file.filename
            # Set Last Modified and Last Accessed times to match remote machine
            os.utime(localPath + path + filename, None, ns=(file.last_access_time, file.last_write_time))
    return n

def copyTo_Remote(conn, shareName, uploadList, remotePath, localPath):
    n = 0
    # Create remote directory structure first
    for (path, fileList) in uploadList.items():
        for file in (f for f in fileList if f.isDirectory):
            filename = file.filename
            # Create remote path if required (recursively)
            createPath_Remote(conn, shareName, remotePath + path + filename)
            # Get remote file attributes
            newFile = conn.getAttributes(shareName, remotePath + path + filename)
            # Set Last Modified and Last Accessed times in remote to match local machine
            os.utime(localPath + path + filename, None, ns=(newFile.last_access_time, newFile.last_write_time))
            n += 1
    # Upload file(s)
    for (path, fileList) in uploadList.items():
        for file in (f for f in fileList if not f.isDirectory):
            filename = file.filename       
            with open(localPath + path + filename, "rb") as f:
                logger.info("Uploading local file: %s"  % (localPath + path + filename))
                file_size = conn.storeFile(shareName, remotePath + path + filename, f)
                logger.info("Upload complete [%s bytes(s)]: %s" % (file_size, (shareName + remotePath + path + filename)))
                f.close()
                # Get remote file attributes
                newFile = conn.getAttributes(shareName, remotePath + path + filename)
                # Set Last Modified and Last Accessed times in remote to match local machine
                os.utime(localPath + path + filename, None, ns=(newFile.last_access_time, newFile.last_write_time))
                n += 1
    # Ensure attributes of local folders match remote
    # NOTE: This is required because uploading a file into a folder changes its attributes
    for (path, fileList) in uploadList.items():
        for file in (f for f in fileList if f.isDirectory):
            filename = file.filename
            # Get remote file attributes
            newFile = conn.getAttributes(shareName, remotePath + path + filename)
            # Set Last Modified and Last Accessed times in remote to match local machine
            os.utime(localPath + path + filename, None, ns=(newFile.last_access_time, newFile.last_write_time))
    return n

#######################################################################################
#                                         MAIN                                        #
#######################################################################################

if __name__ == "__main__":
    # Setup logging
    logger = logging.getLogger()
    tempBuffer = StringIO()
    tempstr_log_handler = logging.StreamHandler(tempBuffer)
    logger.addHandler(tempstr_log_handler)
    stderr_log_handler = logging.StreamHandler()
    logger.addHandler(stderr_log_handler)
    formatter = logging.Formatter(LOG_FORMAT)
    tempstr_log_handler.setFormatter(formatter)
    stderr_log_handler.setFormatter(formatter)
    logger.setLevel(LOG_LEVEL)
    # Print version
    logger.info("Data Syncer started (v%s)" % VERSION_STR)
    # Print script path
    scriptPath = sys.path[0]
    if os.path.isdir(scriptPath):
        scriptPath = os.path.join(sys.path[0], sys.argv[0])
    logger.info("Program executable path: %s" % scriptPath)
    # Check if program configuration XML file exists
    configFilePathXML = os.path.dirname(scriptPath) + '/' + CONFIG_FILENAME_XML
    if not os.path.exists(configFilePathXML):
        logger.error("CONFIG_NOT_FOUND_XML: Could not find program configuration XML file: %s" % (os.path.abspath(configFilePathXML)))
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_CONFIG_NOT_FOUND_XML)
    else:
        logger.info("Found program configuration XML file: %s" % (os.path.abspath(configFilePathXML)))
    # Check if program configuration XSD file exists
    configFilePathXSD = os.path.dirname(scriptPath) + '/' + CONFIG_FILENAME_XSD
    if not os.path.exists(configFilePathXSD):
        logger.error("CONFIG_NOT_FOUND_XSD: Could not find program configuration XSD file: %s" % (os.path.abspath(configFilePathXSD)))
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_CONFIG_NOT_FOUND_XSD)
    else:
        logger.info("Found program configuration XSD file: %s" % (os.path.abspath(configFilePathXSD)))
    # Load program configuration XSD file
    try:
        xmlschema_doc = etree.parse(configFilePathXSD)
        xmlschema = etree.XMLSchema(xmlschema_doc)
    except Exception as e:
        logger.error("PARSE_CONFIG_XSD: Please ensure program configuration XSD file is properly formatted.")
        logger.error(str(e))
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_PARSE_CONFIG_XSD)
    # Load program configuration XML file
    try:
        doc = etree.parse(configFilePathXML)
    except Exception as e:
        logger.error("PARSE_CONFIG_XML: Please ensure program configuration XML file is properly formatted.")
        logger.error(str(e))
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_PARSE_CONFIG_XML)
    # Validate XML
    try:
        xmlschema.assertValid(doc)
        logger.info('Program configuration XML file successfully validated.')
    except Exception as e:
        logger.error("VALIDATE_CONFIG_XML: Configuration XML failed validation.")
        logger.error(str(e))
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_VALIDATE_CONFIG_XML)
    # Parse input arguments
    parser = argparse.ArgumentParser(description='A Python-based tool to synchronise/copy/move data between local and network-accessible paths (v%s).' % VERSION_STR)
    group = parser.add_mutually_exclusive_group(required=True)
    # Dynamically add commands from configuration file
    for folder in doc.xpath('//Configuration/Folder'):
        cmd = folder.xpath('@cmd')[0]
        if cmd == 'h':
            logger.error("HELP_COMMAND_RESERVED: Configuration cannot use 'h' as a command as it is reserved.")
            logger.error('Program will now exit.')
            sys.exit(RETURN_EXIT__ERROR_HELP_COMMAND_RESERVED)
        cmd_long = folder.xpath('@cmd_long')[0]
        if cmd_long == 'help':
            logger.error("HELP_COMMAND_RESERVED: Configuration cannot use 'help' as a long command as it is reserved.")
            logger.error('Program will now exit.')
            sys.exit(RETURN_EXIT__ERROR_HELP_COMMAND_RESERVED)
        desc = folder.xpath('@desc')[0]
        group.add_argument('-' + cmd, '--' + cmd_long, help=desc, action='store_true')
    # Parse arguments
    args = parser.parse_args()        
    # Save folder element for requested command
    for folder in doc.xpath('//Configuration/Folder'):
        cmd_long = folder.xpath('@cmd_long')[0]
        if getattr(args, cmd_long.replace("-", "_")):
            logger.info("Command Requested: %s" % cmd_long)
            f = folder
            break
    # LOG FILE
    loggingMode = doc.xpath('//Configuration/@loggingMode')[0]
    if not loggingMode in loggingModeStrs:
        logger.error("INVALID_LOGGING_MODE: Invalid logging mode: %s" % loggingMode)
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_INVALID_LOGGING_MODE)
    logger.info('Logging Mode = %s' % loggingMode)
    # Check if logging is enabled
    if loggingMode != 'OFF':
        logFilePath = doc.xpath('//Configuration/@logFilePath')[0]
        # Print global log details
        logFileFullPath = os.path.abspath(logFilePath + LOG_FILENAME + LOG_FILENAME_EXT)
        logger.info('Global Log File Path = %s' % logFileFullPath)
        try:
            # Open global log file and append contents of temporary string buffer
            f_temp = open(logFileFullPath, 'a')
            f_temp.write(tempBuffer.getvalue())
            f_temp.close()
            # Add file logger
            file_log_handler_global = logging.FileHandler(logFileFullPath)
            logger.addHandler(file_log_handler_global)
            file_log_handler_global.setFormatter(formatter)
            # Check if local logging is also enabled
            if loggingMode == 'DUAL':
                # Print local log details
                logFileFullPath = os.path.abspath(logFilePath + LOG_FILENAME + '_' + cmd_long + LOG_FILENAME_EXT)
                logger.info('Local Log File Path = %s' % logFileFullPath)
                # Open local log file and append contents of temporary string buffer
                f_temp = open(logFileFullPath, 'a')
                f_temp.write(tempBuffer.getvalue())
                f_temp.close()
                # Add file logger
                file_log_handler_local = logging.FileHandler(logFileFullPath)
                logger.addHandler(file_log_handler_local)
                file_log_handler_local.setFormatter(formatter)
            # Remove temporary logger
            logger.removeHandler(tempstr_log_handler)
        except PermissionError as e1:
            logger.error("LOGFILE_PERMISSION_DENIED: Please check permissions. Could not open/create log file at specified path: %s" % logFileFullPath)
            logger.error(str(e1))
            logger.error('Program will now exit.')
            sys.exit(RETURN_EXIT__ERROR_LOGFILE_PERMISSION_DENIED)
        except Exception as e2:
            logger.error("LOGFILE_OPEN: Could not open/create log file at specified path: %s" % logFileFullPath)
            logger.error(str(e2))
            logger.error('Program will now exit.')
            sys.exit(RETURN_EXIT__ERROR_LOGFILE_OPEN)
    # MAX RETRIES
    maxRetries = int(f.xpath('@maxRetries')[0])
    logger.info('Maximum retries = %d' % maxRetries)
    # RETRY INTERVAL
    retryInterval = int(f.xpath('@retryInterval')[0])
    logger.info('Time between retry attempts = %d second(s)' % retryInterval)
    # OPERATION
    operation = f.xpath('@operation')[0]
    if not operation in operationStrs:
        logger.error("INVALID_OPERATION: Invalid operation: %s" % operation)
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_INVALID_OPERATION)
    logger.info('Operation = %s' % operation)
    # FILE HASH CHECK
    doHashCheck = (f.xpath('@doHashCheck')[0] == BOOLEAN_TRUE_STR)
    logger.info('File Hash Check = %s' % doHashCheck)
    # ALLOW MULTIPLE INSTANCES
    nAllowedEXEInstances = int(f.xpath('@nAllowedEXEInstances')[0])
    logger.info('Number of Allowed EXE Instances = %d' % nAllowedEXEInstances)
    procCount = 0
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name'])
        except psutil.NoSuchProcess:
            pass
        else:
            if pinfo['name'] == EXE_FILENAME:
                procCount += 1
    if procCount > nAllowedEXEInstances:
        logger.error("EXE_INSTANCES_LIMIT_EXCEEDED: Number of %s instances running: %d (Allowed: %d)" % (EXE_FILENAME, procCount, nAllowedEXEInstances))
        logger.error('Program will now exit.')
        sys.exit(RETURN_EXIT__ERROR_EXE_INSTANCES_LIMIT_EXCEEDED)
    # Start operation
    firstRun = True
    nRetries = 0
    while True:
        try:
            print('\r\n')
            if not firstRun:
                # Sleep
                if retryInterval > 0:
                    logger.info("Sleeping for %d second(s) before next retry attempt." % retryInterval)
                    time.sleep(retryInterval)
                logger.info('Retry %d/%d:' % (nRetries, maxRetries))
            firstRun = False
            # SOURCE
            src = f.xpath('Source')[0]
            srcPath = os.path.expandvars(src.xpath('@path')[0])
            if not str(srcPath).endswith('/') and not str(srcPath).endswith('\\'):
                logger.error("INVALID_PATH: Ensure SRC path ends with either a '\\' or '/': %s" % srcPath)
                logger.error('Program will now exit.')
                sys.exit(RETURN_EXIT__ERROR_INVALID_PATH)
            srcPathFilter = eval(src.xpath('@pathFilter')[0])
            srcFileFilter = eval(src.xpath('@fileFilter')[0])
            srcConnMethod = src.xpath('@connectionMethod')[0]
            if not srcConnMethod in connMethodStrs:
                logger.error("INVALID_CONN_METHOD: Invalid connection method (SRC): %s" % srcConnMethod)
                logger.error('Program will now exit.')
                sys.exit(RETURN_EXIT__ERROR_INVALID_CONN_METHOD)
            logger.info("SRC(%s) = %s%s" % (srcConnMethod, srcPath, srcPathFilter))
            logger.info("SRC: File filter = %s" % (srcFileFilter))
            doBackupSrc = (src.xpath('BackupArchive/@enable')[0] == BOOLEAN_TRUE_STR)
            logger.info('SRC: Create backup archive: %s' % doBackupSrc)
            backupArchiveFilenamePrefixSrc = BACKUP_ARCHIVE_FILENAME_PREFIX + src.xpath('BackupArchive/@filenamePrefix')[0]
            logger.info('SRC: Backup archive filename prefix: %s' % backupArchiveFilenamePrefixSrc)
            storeRootFolderInBackupArchiveSrc = (src.xpath('BackupArchive/@storeRootFolder')[0] == BOOLEAN_TRUE_STR)
            logger.info('SRC: Store root folder in backup archive: %s' % storeRootFolderInBackupArchiveSrc)
            testBackupArchiveSrc = (src.xpath('BackupArchive/@test')[0] == BOOLEAN_TRUE_STR)
            logger.info('SRC: Test backup archive: %s' % testBackupArchiveSrc)
            # DESTINATION
            dst = f.xpath('Destination')[0]
            dstPath = os.path.expandvars(dst.xpath('@path')[0])
            if not str(dstPath).endswith('/') and not str(dstPath).endswith('\\'):
                logger.error("INVALID_PATH: Ensure DST path ends with either a '\\' or '/': %s" % dstPath)
                logger.error('Program will now exit.')
                sys.exit(RETURN_EXIT__ERROR_INVALID_PATH)
            dstPathFilter = eval(dst.xpath('@pathFilter')[0])
            dstFileFilter = eval(dst.xpath('@fileFilter')[0])
            dstConnMethod = dst.xpath('@connectionMethod')[0]
            if not dstConnMethod in connMethodStrs:
                logger.error("INVALID_CONN_METHOD: Invalid connection method (DST): %s" % dstConnMethod)
                logger.error('Program will now exit.')
                sys.exit(RETURN_EXIT__ERROR_INVALID_CONN_METHOD)
            logger.info("DST(%s) = %s%s" % (dstConnMethod, dstPath, dstPathFilter))
            logger.info("DST: File filter = %s" % (dstFileFilter))
            doBackupDst = (dst.xpath('BackupArchive/@enable')[0] == BOOLEAN_TRUE_STR)
            logger.info('DST: Create backup archive: %s' % doBackupDst)
            backupArchiveFilenamePrefixDst = BACKUP_ARCHIVE_FILENAME_PREFIX + dst.xpath('BackupArchive/@filenamePrefix')[0]
            logger.info('DST: Backup archive filename prefix: %s' % backupArchiveFilenamePrefixDst)
            storeRootFolderInBackupArchiveDst = (dst.xpath('BackupArchive/@storeRootFolder')[0] == BOOLEAN_TRUE_STR)
            logger.info('DST: Store root folder in backup archive: %s' % storeRootFolderInBackupArchiveDst)
            testBackupArchiveDst = (dst.xpath('BackupArchive/@test')[0] == BOOLEAN_TRUE_STR)
            logger.info('DST: Test backup archive: %s' % testBackupArchiveDst)
            # Check if connection method combination is valid
            if not (srcConnMethod, dstConnMethod) in validConnMethodPairs:
                logger.error("CONN_METHOD_PAIR_NOT_SUPPORTED: Connection method pair not supported (SRC=%s, DST=%s)." % (srcConnMethod, dstConnMethod))
                logger.error('Program will now exit.')
                sys.exit(RETURN_EXIT__ERROR_CONN_METHOD_PAIR_NOT_SUPPORTED)
            # Check if file hashing is supported for connection method combination
            if doHashCheck:
                if not (srcConnMethod, dstConnMethod) in validHashCheckConnMethods:
                    logger.error("CONN_METHOD_PAIR_HASHING_NOT_SUPPORTED: File hash checking not supported for connection method pair (SRC=%s, DST=%s)." % (srcConnMethod, dstConnMethod))
                    logger.error('Program will now exit.')
                    sys.exit(RETURN_EXIT__ERROR_CONN_METHOD_PAIR_HASHING_NOT_SUPPORTED)   
            ########################################
            #             DO OPERATION             #
            ########################################
            logger.info("Starting %s operation..." % operation)
            # Save timestamp
            timestamp = datetime.datetime.now()
            # Get remote contents
            srcDict = _getDict(src, srcPathFilter, srcFileFilter)
            # Get local contents
            dstDict = _getDict(dst, dstPathFilter, srcFileFilter)
            # Do comparison
            logger.info('Diff: Left=SRC, Right=DST')
            diffListSrc, nDiffListSrc = doComparison(srcDict, dstDict)
            logger.info('Diff complete: %d item(s)' % nDiffListSrc)
            logger.info('Diff: Left=DST, Right=SRC')
            diffListDst, nDiffListDst = doComparison(dstDict, srcDict)
            logger.info('Diff complete: %d item(s)' % nDiffListDst)
            ########
            # COPY #
            ########
            if (operation == OPERATION_METHOD_STR_COPY):
                # Do DST backup
                if doBackupDst:
                    # We only create a DST backup if SRC has changes and DST is not empty
                    if ((nDiffListSrc > 0) and (len(dstDict) > 0)):
                        _doBackup(dst, backupArchiveFilenamePrefixDst, timestamp, storeRootFolderInBackupArchiveDst, testBackupArchiveDst)
                # Do SRC backup
                if doBackupSrc:
                    logger.warning("SRC backup is not applicable for COPY operation. SRC backup will not be performed.")
                # Do copy
                n = _copy(src, dst, diffListSrc, doHashCheck)
                logger.info("%s operation finished (%s): %d item(s)" % (operation, timestamp, n))
                ret = RETURN_EXIT__SUCCESS
            ########
            # MOVE #
            ########
            elif (operation == OPERATION_METHOD_STR_MOVE):
                # Do DST backup
                if doBackupDst:
                    # We only create a DST backup if SRC has changes and DST is not empty
                    if ((nDiffListSrc > 0) and (len(dstDict) > 0)):
                        _doBackup(dst, backupArchiveFilenamePrefixDst, timestamp, storeRootFolderInBackupArchiveDst,testBackupArchiveDst)
                # Do SRC backup
                if doBackupSrc:
                    # Do backup before deleting
                    if ((nDiffListDst > 0) or (nDiffListSrc > 0)) and (len(srcDict) > 0):
                        _doBackup(src, backupArchiveFilenamePrefixSrc, timestamp, storeRootFolderInBackupArchiveSrc, testBackupArchiveSrc)
                # Do copy
                n = _copy(src, dst, diffListSrc, doHashCheck)
                # Delete copied items from SRC
                _doDelete(src, diffListSrc, defaultdict(list), backupArchiveFilenamePrefixSrc)
                logger.info("%s operation finished (%s): %d item(s)" % (operation, timestamp, n))
                ret = RETURN_EXIT__SUCCESS
            ########
            # SYNC #
            ########
            elif (operation == OPERATION_METHOD_STR_SYNC):
                # Do DST backup
                if doBackupDst:
                    # We create a DST backup if SRC or DST has changes and DST is not empty
                    if ((nDiffListDst > 0) or (nDiffListSrc > 0)) and (len(dstDict) > 0):
                        _doBackup(dst, backupArchiveFilenamePrefixDst, timestamp, storeRootFolderInBackupArchiveDst, testBackupArchiveDst)   
                # Do SRC backup
                if doBackupSrc:
                    logger.warning("SRC backup is not applicable for SYNC operation. SRC backup will not be performed.")
                # Do copy
                n = _copy(src, dst, diffListSrc, doHashCheck)
                # Remove any files/dirs from DEST not present in SRC
                _doDelete(dst, dstDict, srcDict, backupArchiveFilenamePrefixDst)
                logger.info("%s operation finished (%s): %d item(s)" % (operation, timestamp, n))
                ret = RETURN_EXIT__SUCCESS
            #########
            # CLEAN #
            #########
            elif ((operation == OPERATION_METHOD_STR_CLEAN) or (operation == OPERATION_METHOD_STR_CLEAN_DEL)):
                #  Check if SRC is empty
                if (len(srcDict) > 0):
                    # Operation is only performed if DST contains all files/folders in SRC
                    if (nDiffListSrc == 0):
                        # Do file hash check
                        if doHashCheck:
                            for (path, fileList) in srcDict.items():
                                for file in fileList:
                                    # Check if SRC file exists in DST
                                    if path in dstDict:
                                        f = getSharedFileObject(dstDict[path], file.filename)
                                    else:
                                        f = None
                                    # File with same filename in SRC exists in DST
                                    if f != None and not file.isDirectory:
                                        srcFile_sha = getHash(srcPath + path + file.filename)
                                        dstFile_sha = getHash(dstPath + path + file.filename)
                                        # Check if file hashes match
                                        if srcFile_sha != dstFile_sha:
                                            logger.error("FILE_HASH_MISMATCH: File hashes do not match: SRC(%s)=%s, DST(%s)=%s" % (srcPath + path + file.filename, srcFile_sha, dstPath + path + file.filename, dstFile_sha))
                                            logger.error('Program will now exit.')
                                            sys.exit(RETURN_EXIT__ERROR_FILE_HASH_MISMATCH)
                            logger.info('File hash check successful.')
                        # Do DST backup
                        if doBackupDst:
                            logger.warning("DST backup is not applicable for CLEAN operation. DST backup will not be performed.")
                        # Do SRC backup
                        if doBackupSrc:
                            _doBackup(src, backupArchiveFilenamePrefixSrc, timestamp, storeRootFolderInBackupArchiveSrc, testBackupArchiveSrc)  
                        # Delete items from SRC
                        _doDelete(src, srcDict, defaultdict(list), backupArchiveFilenamePrefixSrc)
                        # Delete source directory
                        if(operation == OPERATION_METHOD_STR_CLEAN_DEL):
                            shutil.rmtree(srcPath, onerror=remove_readonly)
                            logger.info('Deleted local directory: %s' % srcPath)
                        ret = RETURN_EXIT__SUCCESS
                    else:
                        logger.error("CLEAN_OP_DST_DOES_NOT_CONTAIN_SRC: DST does not contain all files/folders in SRC.")
                        logger.error('Program will now exit.')
                        sys.exit(RETURN_EXIT__ERROR_CLEAN_OP_DST_DOES_NOT_CONTAIN_SRC)
                else:
                    logger.warning("SRC is empty.")
                    ret = RETURN_EXIT__CLEAN_OP_SRC_EMPTY
            ########################################
            ########################################
        except (KeyboardInterrupt):
            logger.info('\r\nReceived keyboard interrupt.')
            logger.info('Program will now exit.')
            sys.exit(RETURN_EXIT__KEYBOARD_INT)
        except Exception as e:
            logger.error("OPERATION: Operation failed.")
            logger.error(str(e))
            if nRetries < maxRetries:
                nRetries += 1
                logger.error('Program will retry.')
                continue
            else:
                logger.info('Program will now exit.')
                sys.exit(RETURN_EXIT__ERROR_OPERATION)
        # We hit this break if the command completed successfully
        break

    # Close program (successful run)
    logger.info('Program successfully completed.')
    logger.info('Program will now exit.')
    sys.exit(ret)