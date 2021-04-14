<?php

namespace App\Controllers;

use \Core\View;
use \App\Models\User;
use \App\Auth;
Use \App\Flash;

class Login extends \Core\Controller
{
    /**
     * Show the login page
     *
     * @return void
     */
    public function newAction()
    {
        View::renderTemplate('Login/new.html');
    }


    /**
     * Log in user
     *
     * @return void
     */
    public function createAction()
    {
        $user = User::authenticate($_POST['email'], $_POST['password']);

        $remember_me = isset($_POST['remember_me']);

        if($user){

            Auth::login($user, $remember_me);

            Flash::addMessage('Login succesfull');

            $this -> redirect(Auth::getReturnToPage());
            
        } else {

            Flash::addMessage('Login unsuccessful, please try again', Flash::WARNING);

            View::renderTemplate('Login/new.html',[
                'email' => $_POST['email'],
                'remember_me' => $remember_me
            ]);
        }
    }



    public function destroyAction()
    {
        Auth::logout();
        
        $this -> redirect('/php-mvc/public/login/show-logout-message');
    }


    public function showLogoutMessageAction()
    {
        Flash::addMessage('Logout succesfull');
        
        $this -> redirect('/php-mvc/public');
    }

}