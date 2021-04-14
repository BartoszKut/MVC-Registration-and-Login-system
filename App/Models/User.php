<?php

namespace App\Models;

use PDO;
use \App\Token;

/**
 * Example user model
 *
 * PHP version 7.0
 */
class User extends \Core\Model
{

    /** Error messages
    * @var array */
    public $errors = [];


    /**
     * Class constructor
     * 
     * @param array $data Initial property values
     * 
     * @return void
     */
    public function __construct($data = [])
    {
        foreach ($data as $key => $value){
            $this -> $key = $value;
        };
    }

    /**
     * Save the user model with current property tules
     *
     * @return void
     */
    public function save()   
    {
        $this -> validate();

        if(empty($this -> errors)) {
            $password_hash = password_hash($this -> password, PASSWORD_DEFAULT);

            $sql = 'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)';

            $db = static::getDB();
            $stmt = $db -> prepare($sql);

            $stmt -> bindValue(':name', $this->name, PDO::PARAM_STR);
            $stmt -> bindValue(':email', $this->email, PDO::PARAM_STR);
            $stmt -> bindValue(':password_hash', $password_hash, PDO::PARAM_STR);

            return $stmt -> execute();
        }

        return false;
    }


    public function validate()
    {
        // name
          if($this -> name == ''){
              $this -> errors[] = "Name is required";
          }

        // email adress
          if(filter_var($this -> email, FILTER_VALIDATE_EMAIL) === false) {
              $this -> errors[] = "Invalid email";
          }

          if(static::emailExists($this -> email)) {
              $this -> errors[] = "Email already taken";
          }

        // password
         //if($this -> password != $this -> password_confirmation) {
          //   $this -> errors[] = "Password must match confirmation";
         //}

         if(strlen($this -> password) < 6) {
             $this -> errors[] = "Please enter at least 6 characters for the password";
         }

         if(preg_match('/.*[a-z]+.*/i', $this -> password) == 0) {
             $this -> errors[] = "Password needs al least one letter";
         }

         if(preg_match('/.*\d+.*/i', $this -> password) == 0) {
            $this -> errors[] = "Password needs al least one number";
        }
    }



    public static function emailExists($email)
    {
        return static::findByEmail($email) !== false;
    }



    public static function findByEmail($email)
    {
        $sql = 'SELECT * FROM users WHERE email = :email';

        $db = static::getDB();
        $stmt = $db -> prepare($sql);
        $stmt -> bindParam(':email', $email, PDO::PARAM_STR);

        $stmt -> setFetchMode(PDO::FETCH_CLASS, get_called_class());

        $stmt -> execute();

        return $stmt -> fetch();
    }



    public static function authenticate($email, $password)
    {
        $user = static::findByEmail($email);

        if($user){
            if(password_verify($password, $user -> password_hash)) {
                return $user;
            }
        }
        return false;
    }



    public static function findById($id)
    {
        $sql = 'SELECT * FROM users WHERE id = :id';

        $db = static::getDB();

        $stmt = $db -> prepare($sql);

        $stmt -> bindParam(':id', $id, PDO::PARAM_INT);

        $stmt -> setFetchMode(PDO::FETCH_CLASS, get_called_class());

        $stmt -> execute();

        return $stmt -> fetch();
    }


    public function rememberLogin()
    {
        $token = new Token();
        $hashed_token = $token -> getHash();
        $this -> remember_token = $token->getValue();

        $this -> expiry_timestamp = time() + 60 * 60 * 24 * 30; //30 days from now
        $date_to_rember = date('Y-m-d H:i:s', $this -> expiry_timestamp);


        $sql = 'INSERT INTO remembered_logins (token_hash, user_id, expires_at) VALUES (:token_hash, :user_id, :expires_at)';

        $db = static::getDB();

        $stmt = $db -> prepare($sql);

        $stmt -> bindParam(':token_hash', $hashed_token, PDO::PARAM_STR);
        $stmt -> bindParam(':user_id', $this -> id, PDO::PARAM_INT);
        $stmt -> bindParam(':expires_at', $date_to_rember, PDO::PARAM_STR);

        return $stmt -> execute();
    }
}
