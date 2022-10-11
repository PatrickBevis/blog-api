<?php class BaseModel {

    public function __construct($params, $table)
    {
        $this->table = $table;
        $keys = get_object_vars($params);
        foreach($keys as $k=>$v){
            $this->$k = $v;
        }
    }

    public static function From(&$entry, $table){
        if(is_array($entry)){
            foreach($entry as &$row){
                $row = new BaseModel($row, $table);
            }
            return $entry;
        }
        else{
            return new BaseModel($entry, $table);
        }
    }

    public function addOne($table){
        $dbs = new DatabaseService($table);
        $fk = "Id_".$table;
        if(property_exists($this, $fk)){
            $id = $this->$fk;
            $this->$table = $dbs->selectOne($id);
        }
        else{
            $columns = $dbs->getColumns();
            $fk = "Id_".$this->table;
            if(in_array($fk, $columns)){
                $id = $this->$fk;
                $rows = $dbs->selectWhere("is_deleted = 0 AND $fk = $id");
                $this->$table = array_pop($rows);
            }
        }
        return $this;    
    }

    //addMany
    public function addMany($table){
        $dbs = new DatabaseService($table);
        $columns = $dbs->getColumns();
        $name = $table."_list";
        $fk = "Id_".$this->table;
        if (in_array($fk, $columns)){
            $id = $this->$fk;
            $this->$name = $dbs->selectWhere("is_deleted = 0 AND $fk = $id");
        }
        else{
            $tables = DatabaseService::getTables();
            $rel_table = $table."_".$this->table;
            if(!in_array($rel_table,$tables)){
                $rel_table = $this->table."_".$table;
            }
            $dbs = new DatabaseService($rel_table);
            $fk = "Id_".$this->table;
            $id = $this->$fk;
            $rel_rows = $dbs->selectWhere("$fk = $id");
            $ids = array_column($rel_rows, "Id_".$table);
            $ids = implode( ',', $ids );
            $dbs = new DatabaseService($table);
            $rows = $dbs->selectWhere("is_deleted = 0 AND Id_$table IN ($ids)");
            $this->$name = $rows;
            $bp = true;
        }
        return $this;
    }

    public function addOneToRows($rows){

    }

    public function addManyToRows($rows){
        
    }

}?>