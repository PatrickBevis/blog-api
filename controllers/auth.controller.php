<?php

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;


class AuthController {

    public function __construct($params)
    {
        $method = array_shift($params);
        $this->action = null;

        // if(isset($method)&& ctype_digit($method)){
        //     return $this;
        // }

        $request_body = file_get_contents('php://input');
        $this->body =$request_body ? json_decode($request_body, true) : null;

        $this->table = 'account';

        if($_SERVER['REQUEST_METHOD'] == "POST" && $method = 'login'){ 
            $this->action = $this->login();


        }

        if($_SERVER['REQUEST_METHOD'] == "GET" && $method = 'check'){ 
            $this->action = $this->check();


        }

    }

public function login(){

    $login =filter_var ($this->body['login'], FILTER_SANITIZE_EMAIL);
    if(!filter_var($login, FILTER_VALIDATE_EMAIL)) {
        return ["result" => false];
    }
    $password = $this->body['password'];
    if($login){
        $dbs = new DatabaseService("account");
        
        $where = "login=? AND is_deleted=?";
        $row = $dbs->selectWhere($where, [$login,0]);
        $prefix = $_ENV['config']->hash->prefix;
        $test = $prefix.$row[0]->password;
        if (password_verify($password, $test)){
            $dbs = new DatabaseService("appuser");
            $where = "Id_appUser=? AND is_deleted=?";
        $row = $dbs->selectWhere($where, [$row[0]->Id_appUser,0]);
        $appuser = $row[0];


        $secretKey = $_ENV['config']->jwt->secret;
        $issuedAt = time();
        $expireAt = $issuedAt + 60 * 60* 24;
        $serverName = "blog.api";
        $userRole = $appuser->Id_role;
        $userId = $appuser->Id_appUser;
        $requestData = [
            'iat' => $issuedAt,
            'iss' => $serverName,
            'nbf' => $issuedAt,
            'exp' => $expireAt,
            'userRole' => $userRole,
            'userId' => $userId,
        ];

        $token = JWT::encode($requestData, $secretKey, 'HS512');

        return [ "result" => true , "role" => $appuser -> Id_role, "id" => $appuser->Id_appUser, "token" =>$token];

        }
        return [ "result" => false ];

    }
    return [ "result" => false ];
}

public function check(){
    $headers = apache_request_headers();
    if(isset($_COOKIE['blog'])){
        $token = $_COOKIE['blog'];
    }
    $secretKey = $_ENV['config'] ->jwt->secret;
    if(!empty($token) && !empty($token)){
        try{
        $payload = JWT::decode($token, new Key($secretKey, 'HS512'));
    }catch(Exception $e){
        $payload= null;
    }
    if(isset ($payload) && 
    $payload->iss === "blog.api" &&
    $payload->nbf < time() &&
    $payload->exp > time())
    {
        return ["result" => true, "role" => $payload->userRole, "id" => $payload->userId];
    }
}
return ["result" => false];
}
}

?>