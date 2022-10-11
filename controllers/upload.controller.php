<?php class UploadController {

    public function __construct($params)
    {
        $this->method = array_shift($params);
        $this->action = $this->{$this->method}();
    }

    public function saveImage($path){
        if(isset($_FILES[0]) && $_FILES[0]['error'] == 0){
            $file = $_FILES[0];
            $name = base_convert(time(), 10, 36);
            $ext = explode('/', $file['type'])[1];
            $img_file_fullname = "/images/" . $path . "/" . $name . "." . $ext;
            $img_server_src = $_SERVER["DOCUMENT_ROOT"] . $img_file_fullname;
            if(rename($file['tmp_name'], $img_server_src)){
                $src = "http://" . $_SERVER["SERVER_NAME"]. $img_file_fullname;
                return ["src"=> $src];
            }
        }
        return false;
    }

    public function theme(){
        $result = $this->saveImage("theme");
        return $result;
    }

}?>