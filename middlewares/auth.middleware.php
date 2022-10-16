<?php 

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

class AuthMiddleware {

    public function __construct($req)
    {
        $restrictedRoutes = (array)$_ENV['config']->restricted;

        $params = explode('/', $req);
        $this->id = array_pop($params);
        if(isset($restrictedRoutes[$req])){
            $this->condition = $restrictedRoutes[$req];
        }
    foreach ($restrictedRoutes as $k=>$v){
        $restricted = str_replace(":id", $this->id, $k);
        if($restricted == $req){
            $this->condition = $v;
            break;
        }
    }
    }
    
    public function verify()
    {
        if(isset($this->condition)){
        $headers = apache_request_headers();
        if(isset($headers['Authorization'])){
            $token = $headers['Authorization'];
        }
        $secretKey = $_ENV['config']->jwt->secret;
        if(isset($token) && !empty($token)){
            try{
                $payload = JWT::decode($token, new key($secretKey, 'HS512'));
          } catch(Exception $e){
            $payload = null;

          }
          if (isset($payload) && 
          $payload->iss === "blog.api" &&
          $payload->nbf < time() &&
          $payload->exp > time())
          {
            $userRole = $payload->userRole;
            $userId = $payload->userId;
            $id = $this->id;
            $test = false;
            eval("\$test=".$this->condition);
            if($test){
                return true;
            }
          }
        }
        header('HTTP/1.0 401 Unauthorized');
        die;
        }
    return true;
}
}



?>