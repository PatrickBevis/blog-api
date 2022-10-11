<?php class ThemeDetailController {

    public function __construct($params)
    {
        $id = array_shift($params);
        $this->action = null;
        if(isset($id) && !ctype_digit($id)){
            return $this;
        }
        if($_SERVER['REQUEST_METHOD'] == "GET" && isset($id)){//GET /themeDetail/:id
            $this->action = $this->getData($id);
        }
    }

    public function getData($id){
        require_once 'theme.controller.php';
        $themeCtrl = new ThemeController([$id]);
        $row = $themeCtrl->getOneWith($id,["article"]);
        require_once 'article.controller.php';
        $articleCtrl = new ArticleController([]);
        $articles = $articleCtrl->getAllWith(["appuser"]);
        foreach($row->articles_list as &$article){
            $filtered_articles = array_values(array_filter($articles, 
                function($item) use ($article){
                    return $item->Id_article == $article->Id_article;
                }));
            $article = count($filtered_articles) == 1 ? array_pop($filtered_articles) : null;
        }
       return $row;
    }

}?>