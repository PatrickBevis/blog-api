<?php

class DatabaseService
{

    public function __construct($table)
    {
        $this->table = $table;
        require_once 'models/base.model.php';
    }

    private static $connection = null;
    private function connect(){
        if (self::$connection == null) {
            //Connexion à la DB
            $db_config = $_ENV['config']->db;
            $host = $db_config->host;
            $port = $db_config->port;
            $dbName = $db_config->dbName;
            $dsn = "mysql:host=$host;port=$port;dbname=$dbName";
            $user = $db_config->user;
            $pass = $db_config->pass;
            try {
                $db_connection = new PDO(
                    $dsn,
                    $user,
                    $pass,
                    array(
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8",
                    )
                );
            } catch (PDOException $e) {
                die("Erreur de connexion à la base de données : $e->getMessage()");
            }
            self::$connection = $db_connection;
        }
        return self::$connection;
    }

    public function query($sql, $params = []){
        $statment = $this->connect()->prepare($sql);
        $result = $statment->execute($params);
        return (object)['result' => $result, 'statment' => $statment];
    }

    public function getColumns(){
        $sql = "DESCRIBE $this->table";
        $resp = $this->query($sql, []);
        $columns = $resp->statment->fetchAll(PDO::FETCH_COLUMN);
        return $columns;
    }

    public static function getTables(){
        $dbs = new DatabaseService(null);
        $sql = "SELECT table_name FROM information_schema.tables WHERE table_schema = ?";
        $resp = $dbs->query($sql, [$_ENV['config']->db->dbName]);
        $tables = $resp->statment->fetchAll(PDO::FETCH_COLUMN);
        return $tables;
    }

    public function selectAll($is_deleted = 0){
        $sql = "SELECT * FROM $this->table WHERE is_deleted = ?";
        $resp = $this->query($sql, [$is_deleted]);
        $rows = $resp->statment->fetchAll(PDO::FETCH_CLASS);
        return $rows;
    }

    public function selectWhere($where = "1", $params = []){
        $sql = "SELECT * FROM $this->table WHERE $where;";
        $resp = $this->query($sql, $params);
        $rows = $resp->statment->fetchAll(PDO::FETCH_CLASS);
        return $rows;
    }

    public function selectOne($id){
        $sql = "SELECT * FROM $this->table WHERE is_deleted = ? AND Id_$this->table = ?";
        $resp = $this->query($sql, [0, $id]);
        $rows = $resp->statment->fetchAll(PDO::FETCH_CLASS);
        $row = $resp->result && count($rows) == 1 ? $rows[0] : null;
        return $row;
    }

    
    function insertOne($body = []){ //TODO insertMany
        $columns = "";
        $values = "";
        if(isset($body["Id_$this->table"])){
            unset($body["Id_$this->table"]);
        }
        $valuesToBind = array();
        foreach ($body as $k => $v) {
            $columns .= $k . ",";
            $values .= "?,";
            array_push($valuesToBind, $v);
        }
        $columns = trim($columns, ',');
        $values = trim($values, ',');
        $sql = "INSERT INTO $this->table ($columns) VALUES ($values)";
        $resp = $this->query($sql, $valuesToBind);
        if($resp->result && $resp->statment->rowCount() == 1){
            $insertedId = self::$connection->lastInsertId();
            $row = $this->selectOne($insertedId);
            return $row;
        }
        return false;
    }

    public function insertOneV2($body = []){ //Version condensée
        if(isset($body["Id_$this->table"])){
            unset($body["Id_$this->table"]);
        }
        $columns = implode(",", array_keys($body));
        $values = implode(",", array_map(function (){ return "?"; },$body));
        $valuesToBind = array_values($body);
        $sql = "INSERT INTO $this->table ($columns) VALUES ($values)";
        $resp = $this->query($sql, $valuesToBind);
        if($resp->result && $resp->statment->rowCount() == 1){
            $insertedId = self::$connection->lastInsertId();
            $row = $this->selectOne($insertedId);
            return $row;
        }
        return false;
    }

    function updateOne($body){ //...TODO updateWhere
        $set = "";
        $valuesToBind = array();
        $id = $body["Id_$this->table"];
        if(isset($body["Id_$this->table"])){
            unset($body["Id_$this->table"]);
        }
        foreach($body as $k=>$v){
            $set .= $k."=?,";
            array_push($valuesToBind,$v);
        }
        $set = trim($set,",");
        $where = "Id_$this->table = ?";
        array_push($valuesToBind,$id);
        $sql = "UPDATE $this->table SET $set WHERE $where";
        $resp = $this->query($sql, $valuesToBind);
        if($resp->result){
            $row = $this->selectOne($id);
            return $row;
        }
        return false;
    }

    function updateOneV2($body){ //Version condensée
        $id = $body["Id_$this->table"];
        $where = "Id_$this->table = ?";
        if(isset($body["Id_$this->table"])){
            unset($body["Id_$this->table"]);
        }
        $set = implode(",", array_map(function ($item){ return $item."=?"; }, array_keys($body)));
        $valuesToBind = array_values($body);
        array_push($valuesToBind,$id);
        $sql = "UPDATE $this->table SET $set WHERE $where";
        $resp = $this->query($sql, $valuesToBind);
        if($resp->result && $resp->statment->rowCount() <= 1){
            $row = $this->selectOne($id);
            return $row;
        }
        return false;
    }

    function deleteOne($body){
        $id = $body["Id_$this->table"];
        $where = "Id_$this->table = ?";
        $sql = "DELETE FROM $this->table WHERE $where";
        $resp = $this->query($sql, [$id]);
        if($resp->result && $resp->statment->rowCount() <= 1){
            $row = $this->selectOne($id);
            return !isset($row);
        }
        return false;
    }

}

?>