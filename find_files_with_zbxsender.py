#!/usr/bin/python
# -*- coding: utf-8 -*-
"""find coredump files

Required:
    - zabbix-sender 4.0 or later
    - Python 3.5 or later if want to find files recursively
"""
import os, sys, glob, logging, argparse, functools, time, socket
from subprocess import check_call, CalledProcessError

INTIME = 1800.0
PATTERN = "core*"
IGNORE_LIST = r"{0}.ignore".format(os.path.splitext(os.path.abspath(__file__))[0])
ZBXAGENT_CONF = "/etc/zabbix/zabbix_agentd.conf"
ZBXITEMKEY_CORED = "vfs.file.coredump"

def setup_logger():
    logger = logging.getLogger(sys.argv[0])
    logger.setLevel(logging.INFO)
    logfile = "{0}.log".format(os.path.splitext(os.path.abspath(__file__))[0])
    fh = logging.FileHandler(logfile)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s - [%(module)s - %(funcName)s][%(levelname)s]: %(message)s'
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger

logger = setup_logger()


class HandleExceptions(object):
    """The decorator that handle any exceptions.
        
        Usage:
        @HandleExceptions(logger)

        logger is logging.Logger or child object
    """

    def __init__(self, logger, is_noraise=False):
        """constructor
        
        Args:
            logger ([type]): logging.Logger object
            is_noraise (bool, optional): flag whether raise any catched exceptions
                default to false.
        """
        self.logger = logger
        self.__is_noraise = is_noraise

    def __call__(self, fn):
        @functools.wraps(fn)
        def wrapper_func(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                self.logger.error("Error has occured. function: {0}, error: {1}"
                    .format(str(fn), str(e)))
                if self.__is_noraise:
                    return e
                raise e
        return wrapper_func


class CheckAction(argparse.Action):
    """argparse Custom action
    
    Args:
        argparse ([type]): [description]
    
    Raises:
        FileNotFoundError: [description]
    """
    def __init__(self, option_strings, dest, **kwargs):
        super(CheckAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_strings=None):
        if not os.path.exists(values):
            raise OSError("[Errno 2] No such file or directory: '{0}'"
                .format(values))
        setattr(namespace, self.dest, values)


def benchmark(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        start = 0
        end = 0
        start = time.time()
        ret = fn(*args, **kwargs)
        end = time.time()
        print("{0}: {1}sec".format(fn.__name__, (end - start)))
        return ret
    return wrapper

@HandleExceptions(logger)
def find_files(path, pattern):
    """finding files by matching pattern in the specified path 
    
    Args:
        path (str): find under path
        pattern (str): pattern for finding file. can contain shell-style wildcards.
    Return:
        list of coredump located path. if no coredump, return the empty list instead.
    """
    ver = sys.version_info
    ## recursive option is valid Python 3.5 later
    # index 0 consists "major", 1 "minor"
    if ver[0] >= 3 and ver[1] >= 5:
        path = os.path.join(path, '**')
        res = glob.iglob(os.path.join(path, pattern), recursive=True)
    else:
        res = glob.iglob(os.path.join(path, pattern))
    # pickup type=file only not type=directory
    files = [p for p in res if os.path.isfile(p)]
    return files

@HandleExceptions(logger)
def get_inode(filepath):
    """Get inode of file.
    
    Args:
        filepath (str): absolute path of a file

    Returns:
        [int] stat.ST_INO
    """
    return os.stat(filepath).st_ino

@HandleExceptions(logger)
def get_mtime(filepath):
    """get mtime from a file
    
    Args:
        filepath (str): absolute path of a file
    Return:
        [float] stat.ST_MTIME(last modified timestamp)
    """
    return os.path.getmtime(filepath)

@HandleExceptions(logger)
def is_mtime_intime(mtime, basetime, intime=INTIME):
    """Check whether mtime of the specified file has created within intime
    
    Args:
        mtime (float): file mtime(unixtime)
        basetime (float): unixtime basetime
        intime (float)[optional]: unixtime mtime
    Returns:
        [boolean] return True if (basetime - mtime) within intime, otherwise return False.
    """
    evaluated_time = basetime - mtime
    if evaluated_time < intime or \
       evaluated_time < 0:
        return True
    else:
        False

def send_zabbix_server(value, key, agent_conf="/etc/zabbix/zabbix_agentd.conf"):
    """send value to zabbix-server trapper item
    
    Args:
        value (str): value send to zabbix-server
        key (str): item key
        agent_conf (str)[optional]: zabbix agent config file path.
    
    Returns:
        int: return code of executing zabbix_sender

    Raises:
        FileNotFoundError: zabbix agent config file does not found.
    """
    ## validate arguments
    if not isinstance(value, str):
        value = str(value)
    if not isinstance(key, str):
        key = str(key)
    if not os.path.exists(agent_conf):
        raise FileNotFoundError("zabbix agent config file {0} was not found.".format(agent_conf))

    cmd = [
        "/usr/bin/zabbix_sender",
        "-c",
        str(agent_conf),
        "-s",
        str(socket.gethostname()),
        "-k",
        key,
        "-o",
        value
    ]
    print(cmd)
    try:
        ret = check_call(cmd)
    except CalledProcessError as e:
        logger.exception(e.output)
        logger.error("Failed to send a value to zabbix-server. cmdline: {0}"
            .format(cmd))
        return e.returncode
    logger.info("Sent {0} to zabbix-server trapper item {1}"
        .format(value, key))
    return ret

### main ###
if __name__ == "__main__":

    def __read_ignorelist():
        lines = list()
        with open(IGNORE_LIST) as f:
            lines = f.readlines()
        return lines

    def init(args):
        if not os.path.exists(IGNORE_LIST):
            with open(IGNORE_LIST, 'w') as f:
                pass

        global findpath
        global zbx_itemkey
        global intime
        global pattern
        global zbxagent_conf
        global now
        global ignore_list

        findpath = args.path
        zbx_itemkey = args.key
        intime = args.intime
        pattern = args.pattern
        zbxagent_conf = args.zbxagent_conf
        now = time.time()
        ignore_list = __read_ignorelist()

    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='Finds coredump under this path',
        action=CheckAction, metavar="<SEARCH_PATH>")
    parser.add_argument('-k', '--key', type=str, required=False, default=ZBXITEMKEY_CORED,
        metavar='<ZBX_ITEMKEY>',
        help='Item key. make sure that item type equals "Zabbix trapper"'
    )
    parser.add_argument('--intime', type=float, required=False, default=INTIME,
        metavar='<UNIXTIME>',
        help='Detects a file has mtime within this value. must be float. default to {0}'.format(INTIME))
    parser.add_argument('--pattern', type=str, required=False, default=PATTERN,
        metavar='<PATTERN>',
        help='Pattern of file name. do pattern matching with this value. default to {0}'.format(PATTERN))
    parser.add_argument('--zbxagent_conf', type=str, required=False, default=ZBXAGENT_CONF,
        action=CheckAction, metavar='<ZBXAGENT_CONFIGPATH>',
        help='zabbix-agent config file path. default to {0}'.format(ZBXAGENT_CONF))
    args = parser.parse_args()

    # basepath find coredump
    findpath = ""
    # item key
    zbx_itemkey = ""
    # intime
    intime = float()
    # pattern for pattern matching
    pattern = ""
    # zabbix agent config file path
    zbxagent_conf = ""

    # unixtime at now
    now = float()
    # ignore file list
    ignore_list = list()
    # result set
    result = list()

    init(args)

    # Argument validation
    if not os.path.isdir(findpath):
        sys.exit("{0} does not a valid path. must be the directory.".format(findpath))
    
    # find coredump files
    coredumps = find_files(findpath, pattern)

    if not coredumps:
        logger.info("coredump file didn't found. this program exit")
        sys.exit(0)
    # append latest coredump files to list which will be sent to zabbix-server
    # old coredump files be skipped.
    for coredump in coredumps:
        inode = get_inode(coredump)
        # old files written in ignorefile  be skipped
        if "{0} {1}\n".format(coredump, inode) in ignore_list:
            continue
        # new coredump append to processed list
        if is_mtime_intime(get_mtime(coredump), now, intime=intime):
            logger.info("new coredump file {0} has found within {1}.".format(coredump, intime))
            result.append(coredump)
        # old files append to ignorefile
        else:
            logger.info("new coredump file {0} has found, but within {1} then skip."
                .format(coredump, intime))
            with open(IGNORE_LIST, 'a') as f:
                f.write("{0} {1}\n".format(coredump, inode))
    
    # send found coredump file path to zabbix-server.
    if result:
        logger.info("Start to send values to zabbix-server...")
        for coredump_path in result:
            ret = send_zabbix_server(coredump_path, zbx_itemkey, agent_conf=zbxagent_conf)
            logger.info("zabbix_sender has exited with {0}".format(ret))
    else:
        logger.info("coredump file didn't found within {0} Sec. this program exit"
            .format(intime))
    print("exit")
