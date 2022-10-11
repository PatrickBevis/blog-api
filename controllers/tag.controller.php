<?php class TagController extends DatabaseController {

    public function affectDataToRow(&$row, $sub_rows){
        
        if(isset($sub_rows['article'])){
            $articles = array_values(array_filter($sub_rows['article'], function($item) use ($row) { 
                return $item->Id_tag == $row->Id_tag;
            }));
            if(isset($articles)){
                $row->articles_list = array_column($articles,'article');
            }
        }
    }
}?>