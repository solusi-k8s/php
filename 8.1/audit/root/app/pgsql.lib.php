<?php
# https://phpdelusions.net/pdo_examples/select
#
defined('DSN_URL') ||
    define('DSN_URL','pgsql:host=localhost; port=5432; dbname=dev_test; sslmode=disable; user=dev_test; password=T3st');

function dbConnect($force = false) {
    static $conn = null;
    if ($conn == null || $force) {
        if ($force) {
            msg("force connect");
        }
        $conn = new PDO(DSN_URL);
        if (!$conn) {
            throw new \Exception("cannot connect to db");
        }
    }
    return $conn;
}

function dbPing($pdo) {
    $stmt = $pdo->prepare("select now() as time");
    $stmt->execute([]); 
    $data = $stmt->fetch();
    if (!isset($data['time'])) {
        dbConnect(true);
    }
}

function createTableNginx() {
    $sql = "
    CREATE TABLE IF NOT EXISTS nginx_log(
        id varchar(100) PRIMARY KEY,
        time int8,
        client varchar(255),
        method varchar(20),
        request_url varchar(1000),
        request_protocol varchar(20),
        request_length int,
        status int,
        bytes_sent int,
        body_bytes_sent int,
        referer varchar(1000) null,
        user_agent varchar(1000),
        upstream_addr varchar(255) null,
        request_time float,
        upstream_response_time float null,
        upstream_connect_time float null,
        upstream_header_time float null
    );
    CREATE INDEX IDX_TIME ON nginx_log (time DESC NULLS LAST);

    ";
}
function createTableAudit() {
    $sql = "
    drop table audit_log;
    drop table login_log;
    CREATE TABLE IF NOT EXISTS user_server(
        id  BIGSERIAL PRIMARY KEY,
        server varchar(255),
        user_id varchar(100),
        group_id varchar(100),
        user_name varchar(255),
        group_name varchar(255) null,
        CONSTRAINT UK_UserServer_ServerUserId UNIQUE (server, user_id)
    );
    CREATE TABLE IF NOT EXISTS audit_log(
        id varchar(100) PRIMARY KEY,
        server varchar(255),
        time int8,
        line int8,
        is_system int2 default 0,
        type varchar(255),
        total int8,
        data json null,
        uid int8 null,
        gid int8 null,
        session int8 null,
        pid int8 null,
        username varchar(1000) null,
        hostname varchar(1000) null,
        address varchar(1000) null,
        terminal varchar(1000) null,
        response varchar(1000) null,
        program varchar(1000) null,
        command varchar(1000) null
    );
    -- ALTER TABLE audit_log ADD COLUMN is_system int default 0 null;
    CREATE INDEX IDX_AuditLog_Time ON audit_log (time ASC NULLS LAST);
    CREATE INDEX IDX_AuditLog_IDX01 ON audit_log (time,is_system, type,uid);
    CREATE INDEX IDX_AuditLog_IsSytem ON audit_log (is_system);
    CREATE INDEX IDX_AuditLog_Type ON audit_log (type);
    CREATE INDEX IDX_AuditLog_Uid ON audit_log (uid);
    CREATE INDEX IDX_AuditLog_Session ON audit_log (session);


    CREATE TABLE IF NOT EXISTS login_log(
        id varchar(100) PRIMARY KEY,
        server varchar(255),
        time int8,
        uid int8 null,
        gid int8 null,
        session int8 null,
        pid int8 null,
        username varchar(1000) null,
        hostname varchar(1000) null,
        address varchar(1000) null,
        response varchar(1000) null,
        logout_id varchar(1000) null,
        logout_time int8 null,
        logout_res varchar(1000) null,
        duration int8 null,
        duration_title varchar(1000) null
    );
    CREATE INDEX IDX_LoginTime_Time ON login_log (time ASC NULLS LAST);
    CREATE INDEX IDX_LoginTime_Server ON login_log (server);
    CREATE INDEX IDX_LoginTime_Uid ON login_log (uid);
    CREATE INDEX IDX_LoginTime_Session ON login_log (session);
    CREATE INDEX IDX_LoginTime_Address ON login_log (address);

    CREATE TABLE IF NOT EXISTS audit_log_system(
        id varchar(100) PRIMARY KEY,
        server varchar(255),
        time int8,
        line int8,
        is_system int2 default 0,
        type varchar(255),
        total int8,
        data json null,
        uid int8 null,
        gid int8 null,
        session int8 null,
        pid int8 null,
        username varchar(1000) null,
        hostname varchar(1000) null,
        address varchar(1000) null,
        terminal varchar(1000) null,
        response varchar(1000) null,
        program varchar(1000) null,
        command varchar(1000) null
    );
    CREATE INDEX IDX_AuditLogSystem_Time ON audit_log_system (time ASC NULLS LAST);
    CREATE INDEX IDX_AuditLogSystem_IDX01 ON audit_log_system (time,is_system, type,uid);
    CREATE INDEX IDX_AuditLogSystem_IsSytem ON audit_log_system (is_system);
    CREATE INDEX IDX_AuditLogSystem_Type ON audit_log_system (type);
    CREATE INDEX IDX_AuditLogSystem_Uid ON audit_log_system (uid);
    CREATE INDEX IDX_AuditLogSystem_Session ON audit_log_system (session);

    ";
}

function insertNgixLog($data) {
    #msg("start : process data : " . $data['id']);
    $row = getDataById("nginx_log", $data['id']);
    if ($row === false) {
        $fields = [
            'id' ,
            'time' ,
            'client' ,
            'method' ,
            'request_url' ,
            'request_protocol' ,
            'request_length' ,
            'status' ,
            'bytes_sent' ,
            'body_bytes_sent' ,
            'referer' ,
            'user_agent' ,
            'upstream_addr' ,
            'request_time' ,
            'upstream_response_time' ,
            'upstream_connect_time' ,
            'upstream_header_time' ,
        ];
        $result = insertData("nginx_log", $fields, $data);
        #msg("result insert : " . var_export($result, true));
    } else {
        #msg("data already exists : " . $data['id']);
    }
    #msg("end : process data : " . $data['id']);
}
function insertAuditLog($data) {
    #msg("start : process data : " . $data['id']);
    $row = false;
    if (!empty($data['is_system'])) {
        $row = getDataById("audit_log_system", $data['id']);
    } else {
        $row = getDataById("audit_log", $data['id']);
    }

    if ($row === false) {
        $fields = [
            'id' ,
            'server',
            'time' ,
            'line' ,
            'is_system',
            'type' ,
            'total' ,
            'data' ,
            'uid' ,
            'gid' ,
            'session' ,
            'pid' ,
            'username' ,
            'hostname' ,
            'address' ,
            'terminal' ,
            'response' ,
            'program' ,
            'command' ,
        ];
        if (isset($data['data'])) {
            if (is_array($data['data'])) {
                $data['data'] = json_encode($data['data']);
            }
        }
        if (!isset($data['is_system'])) {
            $data['is_system'] = 0;
        }
        if (!empty($data['is_system'])) {
            $result = insertData("audit_log_system", $fields, $data);
        } else {
            $result = insertData("audit_log", $fields, $data);
        }
        #msg("result insert : " . var_export($result, true));
    } else {
        #msg("data already exists : " . $data['id']);
    }
    #msg("end : process data : " . $data['id']);
}
function insertLoginLog($data) {
    #msg("start : process data : " . $data['id']);
    $row = getDataById("login_log", $data['id']);

    if ($row === false) {
        $fields = [
            'id' ,
            'server',
            'time' ,
            'uid' ,
            'gid' ,
            'session' ,
            'pid' ,
            'username' ,
            'hostname' ,
            'address' ,
            'response' ,
            'logout_id' ,
            'logout_time' ,
            'logout_res' ,
            'duration' ,
            'duration_title' ,
        ];
        if (isset($data['data'])) {
            if (is_array($data['data'])) {
                $data['data'] = json_encode($data['data']);
            }
        }
        $result = insertData("login_log", $fields, $data);
        #msg("result insert : " . var_export($result, true));
    } else {
        #msg("data already exists : " . $data['id']);
    }
    #msg("end : process data : " . $data['id']);
}

function getDataById($table, $id) {
    $pdo = dbConnect();
    $stmt = $pdo->prepare("SELECT * FROM $table WHERE id=:id");
    $stmt->execute(['id' => $id]); 
    $data = $stmt->fetch();
    return $data;
}
function insertData($table, $fields, $data) {
    $pdo = dbConnect();
    $_fields = implode(',', $fields);
    $values = [];
    foreach($fields as $k=>$v) {
        $values[] = ':' . $v;
    }
    $_values = implode(',', $values);
    $sql = "INSERT INTO $table ($_fields) VALUES($_values);";
    //msg("sql : " . $sql);
    $stmt= $pdo->prepare($sql);
    $datas = [];
    foreach($fields as $k=>$v) {
        $datas[$v] = $data[$v] ?? null;
    }
    #print_r($datas);
    return $stmt->execute($datas);
}

function updateData($table, $where, $data, $whereOperator = 'AND') {
    $pdo = dbConnect();
    $updateStr = [];
    foreach($data as $k=>$v) {
        $updateStr[] = $k .'=:v_'.$k;
    }
    $_updateStr = implode(',', $updateStr);
    $whereStr = [];
    foreach($where as $k=>$v) {
        $whereStr[] = $k .'=:w_'.$k;
    }
    $_whereStr = implode(' '.$whereOperator.' ', $whereStr);
    $sql = "UPDATE $table set $_updateStr where $_whereStr;";
    //msg("sql : " . $sql);
    $stmt= $pdo->prepare($sql);
    $datas = [];
    //update for update
    foreach($data as $k=>$v) {
        $datas['v_'.$k] = $v;
    }
    foreach($where as $k=>$v) {
        $datas['w_'.$k] = $v;
    }
    #print_r($datas);
    return $stmt->execute($datas);
}

function getLoginLog($where, $time,$whereOperator = 'AND') {
    $pdo = dbConnect();
    $whereStr = [];
    foreach($where as $k=>$v) {
        $whereStr[] = $k .'=:w_'.$k;
    }
    $_whereStr = implode(' '.$whereOperator.' ', $whereStr);
    $sql = "select * from login_log where time<=$time AND $_whereStr ORDER BY time desc LIMIT 1";
    //msg($sql);
    $stmt= $pdo->prepare($sql);
    $datas = [];
    foreach($where as $k=>$v) {
        $datas['w_'.$k] = $v;
    }
    $stmt->execute($datas);
    $data = $stmt->fetch();
    return $data;
}
function getUserServer($where, $limit = 1, $whereOperator = 'AND') {
    $pdo = dbConnect();
    $whereStr = [];
    foreach($where as $k=>$v) {
        $whereStr[] = $k .'=:w_'.$k;
    }
    $_whereStr = implode(' '.$whereOperator.' ', $whereStr);
    $sql = "select * from user_server where $_whereStr LIMIT " . $limit;
    //msg($sql);
    $stmt= $pdo->prepare($sql);
    $datas = [];
    foreach($where as $k=>$v) {
        $datas['w_'.$k] = $v;
    }
    //msg($datas);
    $stmt->execute($datas);
    $data = $stmt->fetch();
    return $data;
}


function timePlural($value, $unit)
{
    if($value > 1)
    {
        //return $unit . 's';
        return $unit;
    }
    else
    {
        return $unit;
    }
}

function elapsedTimeHumanReadable($sec, $detailLevel = 6, $delimiter = ' ')
{
    $a_sec = 1;
    $a_min = $a_sec * 60;
    $an_hour = $a_min * 60;
    $a_day = $an_hour * 24;
    $a_month = $a_day * 30;
    $a_year = $a_day * 365;

    $text = '';
    $resultStack = array();
    if($sec >= $a_year)
    {
        $years = floor($sec / $a_year);
        $text .= $years . timePlural($years, ' tahun');
        $sec = $sec - ($years * $a_year);
        array_push($resultStack, $text);
    }

    if($sec >= $a_month)
    {
        $months = floor($sec / $a_month);
        $text = $months . ' bulan';
        $sec = $sec - ($months * $a_month);
        array_push($resultStack, $text);
    }

    if($sec >= $a_day)
    {
        $days = floor($sec / $a_day);
        $text = $days . timePlural($days, ' hari');
        $sec = $sec - ($days * $a_day);
        array_push($resultStack, $text);
    }

    if($sec >= $an_hour)
    {
        $hours = floor($sec / $an_hour);
        $text = $hours . timePlural($hours, ' jam');
        $sec = $sec - ($hours * $an_hour);
        array_push($resultStack, $text);
    }

    if($sec >= $a_min)
    {
        $minutes = floor($sec / $a_min);
        $text = $minutes . timePlural($minutes, ' menit');
        $sec = $sec - ($minutes * $a_min);
        array_push($resultStack, $text);
    }

    if($sec >= $a_sec)
    {
        $seconds = floor($sec / $a_sec);
        $text = $sec . timePlural($seconds, ' detik');
        $sec = $sec - ($sec * $a_sec);
        array_push($resultStack, $text);
    }
    if (empty($resultStack)) {
        return '';
    }

    $result = $resultStack[0];
    for($i = 1; $i <= $detailLevel - 1; $i++)
    {
        if(!empty($resultStack[$i]))
        {
            $result .= $delimiter . $resultStack[$i];
        }
    }

    return $result;
}