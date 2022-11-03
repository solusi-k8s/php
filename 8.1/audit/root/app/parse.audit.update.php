#!/usr/local/bin/php -q
<?php
function msg($msg) {
    if (is_array($msg)) {
        $msg = json_encode($msg);
    }
    echo "[".date("r")."] : " . $msg . PHP_EOL;
}
$cfg = __DIR__ .  '/cfg.inc.php';
if (file_exists($cfg)) {
    include $cfg;
}

$excludeProgam = [];
$excludeCommand = [];
$filepasswd = "/etc/passwd";
$filegroup = "/etc/group";
defined('HOSTNAMETRIM') || define('HOSTNAMETRIM','monitoring_audit-extractor');

include __DIR__ . '/' . 'pgsql.lib.php';

echo DSN_URL . PHP_EOL;

$startPage = $argv[1] ?? 0;
$endPage = $argv[2] ?? 10;
$isUpdate = $argv[3] ?? 0;

$pdo = dbConnect();

function updateDataAudit($isUpdate,$where, $data, $whereOperator = 'AND') {
    $table = 'audit_log';
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
    msg("sql : " . $sql);
    $stmt= $pdo->prepare($sql);
    $datas = [];
    //update for update
    foreach($data as $k=>$v) {
        $datas['v_'.$k] = $v;
    }
    foreach($where as $k=>$v) {
        $datas['w_'.$k] = $v;
    }
    msg($datas);
    #print_r($datas);
    if ($isUpdate) {
        $result = $stmt->execute($datas);
        var_dump($result);
    }
}


for ($i=$startPage; $i<=$endPage; $i++) {
    $limit = 100;
    $offset = $limit * $i;
    $sql = "SELECT * FROM audit_log where is_system=0 limit 100 OFFSET $offset";
    msg("execute : " . $sql);
    $stmt = $pdo->query($sql);
    while ($row = $stmt->fetch()) {
        //echo print_r($row);
        $updateWhere = [];
        $updateWhere['id'] = $row['id'];
        $updateData = [];

        if (empty($row['username'])) {
            $userData = getUserServer(['server'=>$row['server'], 'user_id' => $row['uid']]);
            if (isset($userData['user_name'])) {
                $updateData['username'] = $userData['user_name'];
            }    
        }
        $rowData = json_decode($row['data'], true);
        //print_r($rowData);
        if (isset($rowData['syscall'])) {
            if (isset($rowData['syscall']['tty']) && $rowData['syscall']['tty'] == '(none)') {
                $updateData['is_system'] = 2;
            }
        }
        if (!empty($updateData)) {
            //print_r($rowData);
            print_r($updateData);
            echo "username : " . $row['username'] . " : ";
            updateDataAudit($isUpdate,$updateWhere,$updateData);
        }
    }

}
