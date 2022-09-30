#!/usr/local/bin/php -q
<?php
function msg($msg) {
    if (is_array($msg)) {
        $msg = json_encode($msg);
    }
    echo "[".date("r")."] : " . $msg . PHP_EOL;
}
if (empty($argv[1])) {
    msg("input filenaname");
    exit(100);
}
$filename = $argv[1];
if (!file_exists($filename)) {
    msg("file not exists : " . $filename);
    exit (100);
}
$cfg = __DIR__ .  '/cfg.inc.php';
$excludeProgam = [];
$excludeCommand = [];
$filepasswd = "/etc/passwd";
$filegroup = "/etc/group";

if (file_exists($cfg)) {
    include $cfg;
}
defined('HOSTNAMETRIM') || define('HOSTNAMETRIM','monitoring_audit-extractor');

//echo HOSTNAMETRIM;exit;

$hostname = gethostname();
if (!empty($argv[2])) {
    $hostname = $argv[2];
}

//echo $hostname; exit;

$hostname = trim($hostname, HOSTNAMETRIM);


include __DIR__ . '/' . 'pgsql.lib.php';

processUserSystem();
// exit;

if ($file = fopen($filename, "r")) {
    $lineNumber = 0;
    $finalResult = [];
    while(!feof($file)) {
        $lineNumber++;
        $line = fgets($file);
        $line = trim($line);
        #$line = trim($line);
        $hash = hash("sha256", trim($line));
        if (preg_match('#^type=([A-Z_]+) msg=audit\(([a-z0-9\.]+)\:([0-9]+)\): (.*)#', $line, $matches) > 0) {
            #echo ("$lineNumber : $hash : #$line#");
            $type = $matches[1];
            $time = $matches[2];
            $procLine = $matches[3];
            $process = $matches[4];
            $result = [];
            switch($type) {
                case "EXECVE" :
                    //$result = processGlobal('EXECVE',$hash, $time,$procLine,$process, $line);
                    $result = processExecve($hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                case "SYSCALL":
                    $result = processSyscall($hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                case "PATH":
                    $result = processPath($hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                case "LOGIN":
                    $result = processGlobal('LOGIN',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;    
                case 'CRED_REFR':
                case 'USER_END':
                case "USER_ACCT":
                case "USER_ACCT":
                case "USER_START":
                case 'USER_LOGIN':
                case 'USER_AUTH':
                case 'CRED_DISP':
                    $result = processUser($type,$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                /*
                case "USER_ACCT":
                    $result = processGlobal('USER_ACCT',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                case "LOGIN":
                    $result = processGlobal('CRED_ACQ',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                //user start ssh process
                case "USER_START":
                    $result = processGlobal('USER_START',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                case "USER_LOGIN":
                    $result = processGlobal('USER_LOGIN',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                //user LOGIN, after USER_START    
                case "CRED_REFR":
                    $result = processGlobal('CRED_REFR',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                //user logout
                case "USER_END":
                    $result = processGlobal('USER_END',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                case "CRED_DISP":
                    $result = processGlobal('CRED_DISP',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                */
                case "CWD":
                    $result = processGlobal('CWD',$hash, $time,$procLine,$process, $line);
                    #print_r($result);
                    break;
                    
                // default:
                //     msg($line);
                }
            #print_r($matches);
            if (!empty($result)) {
                if (isset($finalResult[$procLine])) {
                    $finalResult[$procLine][] = $result;
                } else {
                    $finalResult[$procLine] = [];
                    $finalResult[$procLine][] = $result;
                }
            }

        }
    }
    fclose($file);
    if (isset($argv[3]) && $argv[3] == 'test') {
        echo json_encode($finalResult,JSON_PRETTY_PRINT);
        exit;
    }
    // print_r($finalResult);
    //echo PHP_EOL;
    processFinal($finalResult);
}

function processUserSystem() {
    global $hostname, $filepasswd, $filegroup;
    $userServerField = [
        //'id',
        'server',
        'user_id',
        'group_id',
        'user_name',
        'group_name',
    ];
    if ($file = fopen($filepasswd, "r")) {
        $lineNumber = 0;
        $finalResult = [];
        while(!feof($file)) {
            $lineNumber++;
            $line = fgets($file);
            $lines = explode(':', $line);
            if (count($lines) < 5) {
                continue;
            }
            //print_r($lines);
            $data = [];
            $data['server'] = $hostname;
            $data['user_name'] = $lines[0];
            $data['user_id'] = $lines[2];
            $data['group_id'] = $lines[3];
            $dataWhere = [];
            $dataWhere['server'] = $hostname;
            $dataWhere['user_name'] = $lines[0];
            $dataWhere['user_id'] = $lines[2];
            $userData = getUserServer($dataWhere);
            if ($userData === false) {
                insertData('user_server', $userServerField, $data);
            }
        }
    }
    if ($file = fopen($filegroup, "r")) {
        $lineNumber = 0;
        $finalResult = [];
        while(!feof($file)) {
            $lineNumber++;
            $line = fgets($file);
            $lines = explode(':', $line);
            if (count($lines) < 3) {
                continue;
            }
            $dataWhere = [];
            $dataWhere['server'] = $hostname;
            $dataWhere['group_id'] = $lines[2];
            $data = [];
            $data['group_name'] = $lines[0];
            updateData('user_server', $dataWhere, $data);
        }
    }

}
function processExecve($hash,$time,$procLine,$process, $raw) {
    #echo "process : ${process}" . PHP_EOL;
    #preg_match_all('#^argc=([0-9]+)(( a([0-9]+)=\"([0-9A-Za-z\-\/]+)\")+)#', $process, $matches);
    if (preg_match('#^argc=([0-9]+) (.*)#', $process, $matches) > 0) {
        $total = $matches[1];
        $tmp = $matches[2];
        if (preg_match_all('#(a([0-9]+)=(.*?) )#',$tmp." ", $matches2) > 0) {
            #print_r($matches2);
            if (!isset($matches2[3])) {
                return [];
            }
            foreach($matches2[3] as $k=>$v) {
                $matches2[3][$k] = trim($v,'"');
            }
            $cmd = $matches2[3];
            $datas = [
                'argc' => $total,
            ];
            foreach($cmd as $k=>$v) {
                $datas['a' . $k]=$v;
            }
            $totalCmd = count($cmd);
            if ($total != $totalCmd) {
                msg($raw);
                throw new \Exception("failed process EXECVE");
            }
            return [
                'hash' => $hash,
                'time' => $time * 1000,
                'line' => $procLine,
                'type' => 'EXECVE',
                'total' => $total + 1,
                'command' => implode(' ', $cmd),
                'data' => $datas,
                'raw' => $raw,
            ];
        }
        #print_r($matches2);
    
    }
    return [];
}

function processExecveX($hash,$time,$procLine,$process, $raw) {
    #msg($process);
    if (preg_match_all('#([a-zA-Z0-0]+)\=(.*?) #',$process." ", $matches)>0) {
        #echo $process . PHP_EOL;
        #print_r($matches);
        $m1 = $matches[1];
        $m2 = $matches[2];
        $datas = [];
        foreach($m1 as $k=>$v) {
            $datas[$v] = trim($m2[$k],'"');
        }
        return [
            'hash' => $hash,
            'time' => $time * 1000,
            'line' => $procLine,
            'type' => 'EXECVE',
            'total' => count($m1),
            'data' => $datas,
            'raw' => $raw,
        ];
    }
    return [];

}

function processSyscall($hash,$time,$procLine,$process, $raw) {
    #msg($process);
    if (preg_match_all('#([a-zA-Z0-0]+)\=(.*?) #',$process." ", $matches)>0) {
        $m1 = $matches[1];
        $m2 = $matches[2];
        $datas = [];
        foreach($m1 as $k=>$v) {
            $datas[$v] = trim($m2[$k],'"');
        }
        return [
            'hash' => $hash,
            'time' => $time * 1000,
            'line' => $procLine,
            'type' => 'SYSCALL',
            'total' => count($m1),
            'data' => $datas,
            'raw' => $raw,
        ];
    }
    return [];
}
function processPath($hash,$time,$procLine,$process, $raw) {
    #msg($process);
    if (preg_match_all('#([a-zA-Z0-0]+)\=(.*?) #',$process." ", $matches)>0) {
        $m1 = $matches[1];
        $m2 = $matches[2];
        $datas = [];
        foreach($m1 as $k=>$v) {
            $datas[$v] = trim($m2[$k],'"');
        }
        return [
            'hash' => $hash,
            'time' => $time * 1000,
            'line' => $procLine,
            'type' => 'PATH',
            'total' => count($m1),
            'data' => $datas,
            'raw' => $raw,
        ];
    }
    return [];

}

function processGlobal($type,$hash,$time,$procLine,$process, $raw) {
    #msg($process);
    if (preg_match_all('#([a-zA-Z0-0]+)\=(.*?) #',$process." ", $matches)>0) {
        $m1 = $matches[1];
        $m2 = $matches[2];
        $datas = [];
        foreach($m1 as $k=>$v) {
            $datas[$v] = trim($m2[$k],'"');
        }
        return [
            'hash' => $hash,
            'time' => $time * 1000,
            'line' => $procLine,
            'type' => $type,
            'total' => count($m1),
            'data' => $datas,
            'raw' => $raw,
        ];
    }
    return [];
}
function processUser($type,$hash,$time,$procLine,$process, $raw) {
    #msg($process);
    if (preg_match_all('#pid=(.*?) uid=(.*?) auid=(.*?) ses=(.*?) msg=\'(.*)\'#',$process, $matches)>0) {
        $datas = [];
        $datas['pid'] = $matches[1][0];
        $datas['uid'] = $matches[2][0];
        $datas['auid'] = $matches[3][0];
        $datas['ses'] = $matches[4][0];
        $msg = $matches[5][0];
        $datas['msg'] = [];
        if (preg_match_all('#([a-zA-Z0-0]+)\=(.*?) #',$msg." ", $matches2)>0) {
            $m1 = $matches2[1];
            $m2 = $matches2[2];
            foreach($m1 as $k=>$v) {
                $datas['msg'][$v] = trim($m2[$k],'"');
            }    
        }    

        return [
            'hash' => $hash,
            'time' => $time * 1000,
            'line' => $procLine,
            'type' => $type,
            'total' => count($m1),
            'data' => $datas,
            'raw' => $raw,
        ];
    }
    return [];

}



function processFinal($data) {
    foreach($data as $row) {
        //foreach($row as $k=>$v) {
        //}
        //process USER_ACCT

        if (isset($row[1]['type']) && $row[1]['type'] == 'EXECVE' && $row[0]['type'] == 'SYSCALL') {
            //msg("process EXECVE");
            processExecveData($row);
            continue;
        }
        //USER_LOGIN = tidak di process
        if (in_array($row[0]['type'], ['USER_ACCT', 'CRED_REFR','CRED_DISP'])) {
            //msg("process UserAcct");
            processUserData($row);
            continue;
        }
        //process USER_START
        if (in_array($row[0]['type'], ['USER_START','USER_AUTH'])) {
            //msg("process UserStart");
            processUserStart($row);
            continue;
        }
        if ($row[0]['type'] == 'USER_END') {
            //msg("process UserAcct");
            processUserData($row);
            updateUserLog($row);
            continue;
        }
    }
}
function processUserData($row) {
    global $hostname;
    if (count($row) > 1) {
        throw new \Exception("invalid data " . $row['0']['type']);
    }
    $row = $row[0];
    $data = [];
    $data['id'] = $row['hash'];
    $data['server'] = $hostname;
    $data['time'] = $row['time'];
    $data['line'] = $row['line'];
    $data['type'] = $row['type'];
    $data['total'] = $row['total'];
    $data['data'] = $row['data'];
    //$data['uid'] = $row['data']['uid'];
    //$data['gid'] = $row['data']['auid'];

    $data['uid'] = $row['data']['auid'];
    $data['gid'] = $row['data']['auid'];

    $data['session'] = $row['data']['ses'];
    $data['pid'] = $row['data']['pid'];
    $data['username'] = $row['data']['msg']['acct'];
    $data['hostname'] = $row['data']['msg']['hostname'];
    $data['address'] = $row['data']['msg']['addr'];
    $data['terminal'] = $row['data']['msg']['terminal'];
    $data['response'] = $row['data']['msg']['res'];
    $data['program'] = $row['data']['msg']['exe'];
    $data['command'] = null;
    insertAuditLog($data);
}
function processUserStart($row) {
    global $hostname;
    if (count($row) > 1) {
        throw new \Exception("invalid data " . $row['0']['type']);
    }
    $row = $row[0];
    $data = [];
    $data['id'] = $row['hash'];
    $data['server'] = $hostname;
    $data['time'] = $row['time'];
    $data['line'] = $row['line'];
    $data['type'] = $row['type'];
    $data['total'] = $row['total'];
    $data['data'] = $row['data'];
    //$data['uid'] = $row['data']['uid'];
    //$data['gid'] = $row['data']['auid'];

    $data['uid'] = $row['data']['auid'];
    $data['gid'] = $row['data']['auid'];

    $data['session'] = $row['data']['ses'];
    $data['pid'] = $row['data']['pid'];
    $data['username'] = $row['data']['msg']['acct'];
    $data['hostname'] = $row['data']['msg']['hostname'];
    $data['address'] = $row['data']['msg']['addr'];
    $data['terminal'] = $row['data']['msg']['terminal'];
    $data['response'] = $row['data']['msg']['res'];
    $data['program'] = $row['data']['msg']['exe'];
    $data['command'] = null;
    insertAuditLog($data);

    $dataUserLog = [];
    $dataUserLog['id'] = $row['hash'];
    $dataUserLog['server'] = $hostname;
    $dataUserLog['time'] = $row['time'];
    //$dataUserLog['uid'] = $row['data']['uid'];
    //$dataUserLog['gid'] = $row['data']['auid'];
    $dataUserLog['uid'] = $row['data']['auid'];
    $dataUserLog['gid'] = $row['data']['auid'];

    $dataUserLog['session'] = $row['data']['ses'];
    $dataUserLog['pid'] = $row['data']['pid'];
    $dataUserLog['username'] = $row['data']['msg']['acct'];
    $dataUserLog['hostname'] = $row['data']['msg']['hostname'];
    $dataUserLog['address'] = $row['data']['msg']['addr'];
    $dataUserLog['response'] = $row['data']['msg']['res'];
    insertLoginLog($dataUserLog);
}
function updateUserLog($row) {
    global $hostname;
    if (count($row) > 1) {
        throw new \Exception("invalid data " . $row['0']['type']);
    }
    $row = $row[0];

    $dataWhere = [];
    $dataWhere['server'] = $hostname;
    //$dataWhere['uid'] = $row['data']['uid'];
    //$dataWhere['gid'] = $row['data']['auid'];

    $dataWhere['uid'] = $row['data']['auid'];
    $dataWhere['gid'] = $row['data']['auid'];

    $dataWhere['session'] = $row['data']['ses'];
    $dataWhere['pid'] = $row['data']['pid'];
    $dataWhere['response'] = 'success';
    
    $dataUserLog = [];
    $dataUserLog['logout_id'] = $row['hash'];
    $dataUserLog['logout_time'] = $row['time'];
    $dataUserLog['logout_res'] = $row['data']['msg']['res'];

    $loginData = getLoginLog($dataWhere, $dataUserLog['logout_time']);
    if (!empty($loginData['time'])) {
        $dataWhere['id'] = $loginData['id'];
        $loginTime = $loginData['time'];
        $dataUserLog['duration'] = floor(($dataUserLog['logout_time'] - $loginTime)/1000);
        $dataUserLog['duration_title'] = elapsedTimeHumanReadable($dataUserLog['duration']);
    }
    updateData('login_log', $dataWhere, $dataUserLog);
}
function processExecveData($row) {
    global $hostname, $excludeProgam, $excludeCommand;
    //print_r($row);
    if (count($row) < 2) {
        throw new \Exception("invalid data " . $row['0']['type']);
    }
    $row0 = $row[0];
    $row1 = $row[1];
    $data = [];
    $data['id'] = $row1['hash'];
    $data['server'] = $hostname;
    $data['time'] = $row1['time'];
    $data['line'] = $row1['line'];
    $data['type'] = $row1['type'];
    $data['total'] = $row1['total'];
    $datas = $row1['data'];
    $datas['syscall'] = $row0['data'];
    if (isset($row[2]['type']) && $row[2]['type']=='CWD') {
        $datas['cwd'] = $row[2]['data'];
    }
    if (isset($row[3]['type']) && $row[3]['type']=='PATH') {
        $datas['path'] = $row[3]['data'];
    }
    $data['data'] = $datas;
    //$data['uid'] = $row0['data']['uid'];
    //$data['gid'] = $row0['data']['auid'];

    $data['uid'] = $row0['data']['uid'];
    $data['gid'] = $row0['data']['gid'];

    $data['session'] = $row0['data']['ses'];
    $data['pid'] = $row0['data']['pid'];
    //$data['username'] = $row['data']['msg']['acct'];
    //$data['hostname'] = $row['data']['msg']['hostname'];
    //$data['address'] = $row['data']['msg']['addr'];
    $data['terminal'] = $row0['data']['tty'];
    $data['response'] = $row0['data']['success'] == 'yes' ? 'success' : 'failed';
    $data['program'] = $row0['data']['exe'];
    $data['command'] = $row1['command'];
    $excludeProgamDefault = [
        '/usr/bin/docker-init',
        'docker-init',
        '/bin/sleep',
        'sleep',
        '/bin/date',
        'date',
        '/usr/bin/runc',
        'runc',
        '/bin/mktemp',
        'mktemp',
    ];
    $excludeProgamData = array_merge($excludeProgamDefault, $excludeProgam);
    if (in_array($data['program'], $excludeProgamData)) {
        return;
    }
    $excludeCommandDefault = [
        'docker-init --version',
        'wc -l /var/log/audit/audit.log',
        '/usr/local/bin/php -q /app/parse.audit.php /tmp/tmp',
        'rm -vf /tmp/tmp',
        'wc -l /var/log/nginx/apm.access.log',
        '/bin/sh /usr/bin/lesspipe',
        'basename /usr/bin/lesspipe',
        'dirname /usr/bin/lesspipe',
    ];
    $excludeCommandData = array_merge($excludeCommandDefault, $excludeCommand);
    if (in_array($data['command'], $excludeCommandData)) {
        return;
    }
    foreach($excludeCommandData as $cmd) {
        if (strpos($data['command'], $cmd) !== false) {
            return;
        }
    }
    //get login data
    $dataWhere = [];
    $dataWhere['server'] = $hostname;

    $dataWhere['uid'] = $row0['data']['auid'];
    $dataWhere['session'] = $row0['data']['ses'];
    $dataWhere['pid'] = $row0['data']['pid'];
 

    $loginData = getLoginLog($dataWhere, $data['time']);
    if (!empty($loginData['time'])) {
        $data['username'] = $loginData['username'];
    }
    if (empty($data['username'])) {
        $userData = getUserServer(['server'=>$hostname, 'user_id' => $data['uid']]);
        if (isset($userData['user_name'])) {
            $data['username'] = $userData['user_name'];
        }
    }
    //check "tty": "(none)",
    if (isset($row0['data']['tty']) && $row0['data']['tty'] == '(none)') {
        $data['is_system'] = 1;

    }
    //command = "-bash"
    //check "tty": "(none)",
    $commandList = [
        '-bash',
        '/usr/bin/locale-check C.UTF-8'
    ];
    if (isset($row1['command']) && in_array($row1['command'],$commandList)) {
        $data['is_system'] = 1;
    }

    // if ($data['id'] == 'd83f3afcb52d0c9950f0db66e5e76b1cb2dfe4ac424aac03b8eadbd5b553d8c5') {
    //     echo "test";
    //     print_r($data);
    //     echo "kelluar";
    //     exit;
    // }




    insertAuditLog($data);
}

