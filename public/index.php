<?php

/**
 * Front controller
 * 
 * PHP version 7.0
 */
 
ini_set('session.cookie_lifetime', '864000'); // 10 days in seconds


/**
 * Composer
 */
require dirname(__DIR__) . '/vendor/autoload.php';

//Twig_Autoleader::register();


/**
 * Error and Exception handling
 */
error_reporting(E_ALL);
set_error_handler('Core\Error::errorHandler');
set_exception_handler('Core\Error::exceptionHandler');



session_start();


/**
 * Routing
 */
$router = new Core\Router();

// Add the routes
$router->add('', ['controller' => 'Home', 'action' => 'index']);
$router->add('login', ['controller' => 'Login', 'action' => 'new']);
$router->add('logout', ['controller' => 'Login', 'action' => 'destroy']);
$router->add('{controller}/{action}');
    
$router->dispatch($_SERVER['QUERY_STRING']);