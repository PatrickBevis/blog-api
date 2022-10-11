<?php class AppuserController extends DatabaseController {

    public function affectDataToRow(&$row, $sub_rows){
        
        if(isset($sub_rows['account'])){
            $accounts = array_filter($sub_rows['account'], function($item) use ($row) { 
                return $item->Id_appUser == $row->Id_appUser;
            });
            $row->account = count($accounts) == 1 ? array_shift($accounts) : null;
        }
        
        if(isset($sub_rows['role'])){
            $roles = array_filter($sub_rows['role'], function($item) use ($row) { 
                return $item->Id_role == $row->Id_role;
            });
            $row->role = count($roles) == 1 ? array_shift($roles) : null;
        }
        
        if(isset($sub_rows['article'])){
            $articles = array_values(array_filter($sub_rows['article'], function($item) use ($row) { 
                return $item->Id_appUser == $row->Id_appUser;
            }));
            if(isset($articles)){
                $row->articles_list = $articles;
            }
        }

        if(isset($sub_rows['comment'])){
            $comments = array_values(array_filter($sub_rows['comment'], function($item) use ($row) { 
                return $item->Id_appUser == $row->Id_appUser;
            }));
            if(isset($comments)){
                $row->comments_list = $comments;
            }
        }
    }

}?>