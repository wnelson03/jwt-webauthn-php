<?php
require_once 'main.php';
ini_set('display_errors', 0);

set_exception_handler(function ($exception) {
	http_response_code(500);
        $response = new Response(status: 500, error: $exception->getMessage(), env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
        $response->send();
});

switch($_SERVER['REQUEST_URI']) {
        case "/api/v1/auth/login":
                $email = htmlentities(sha1(strtolower($_POST['email']))); // set to lower-case in the event someone types differently, hash with SHA1 for privacy
                $password = htmlentities($_POST['password']);
                $account = new Account(email: $email, auth: true);
                if($account->login($password)) {
                        $response = new Response(status: 200, message: "Successfully accessed account", env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
                        $response->send();
                }
                break;
        case "/api/v1/auth/register":
                $email = htmlentities(sha1(strtolower($_POST['email']))); // set to lower-case in the event someone types differently, hash with SHA1 for privacy
                $password = htmlentities($_POST['password']);
                $account = new Account(email: $email, auth: true);
                if($account->register($password)) {
                        $response = new Response(status: 200, message: "Successfully registered account", env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
                        $response->send();
                }
                break;
        case "/api/v1/auth/logout":
                setcookie('accessToken', '', 0, '/'); // delete cookie on browser
                $response = new Response(status: 200, message: "Logged out successfully.", env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
                $response->send();
                break;
        case "/api/v1/self":
                $session = new Session(sessionName: "accessToken");
                $account = $session->get();
                if(!$account->isAuthenticated()) {
                        setcookie('accessToken', '', 0, '/'); // delete cookie on browser
                        throw new Exception("Not logged in");
                }

                $response = new Response(status: 200, data: (array) $account, env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
                $response->send();
                break;
        case "/api/v1/auth/webauthn?fn=getCreateArgs":
        case "/api/v1/auth/webauthn?fn=getGetArgs":
        case "/api/v1/auth/webauthn?fn=processCreate":
        case "/api/v1/auth/webauthn?fn=processGet":
                $session = new Session(sessionName: "accessToken");
                $account = $session->get();

                require_once '../src/WebAuthn.php';
                /*
                 * Copyright (C) 2022 Lukas Buchs
                 * license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
                 * 
                */
                $fn = filter_input(INPUT_GET, 'fn');
                $post = trim(file_get_contents('php://input'));
                $userId = bin2hex(openssl_random_pseudo_bytes(10));
                if ($post) {
                        $post = json_decode($post);
                }
                $formats = array();
                $formats[] = 'none';

                $rpId = $_SERVER['HTTP_HOST'];

                // cross-platform: true, if type internal is not allowed
                //                 false, if only internal is allowed
                //                 null, if internal and cross-platform is allowed
                $crossPlatformAttachment = null;
                
                // new Instance of the server library.
                // make sure that $rpId is the domain name.
                $WebAuthn = new lbuchs\WebAuthn\WebAuthn('jwt-webauthn-php', $rpId, $formats);

                session_start(); // for saving challenge temporarily. Redis could be used instead.

                $db = new Database("localhost", "root", "", "jwt-webauthn-php");

                switch($fn) {
                        case "getCreateArgs":
                                $createArgs = $WebAuthn->getCreateArgs($userId, $account->id, "", 20, 0, "discouraged", $crossPlatformAttachment);

                                // save challange to session. you have to deliver it to processGet later.
                                $_SESSION['challenge'] = $WebAuthn->getChallenge();

                                header('Content-Type: application/json');
                                die(json_encode($createArgs));
                                break;
                        case "getGetArgs":
                                $ids = array();

                                // load registrations from session stored there by processCreate.

                                $query = $db->query("SELECT * FROM `securityKeys` WHERE `account` = ?", [$account->id]);
	                        	if ($query->num_rows > 0) {
	                        		while ($row = mysqli_fetch_array($query->result)) {
	                        			$ids[] = base64_decode($row["credentialId"]);
	                        		}
	                        	}
                                
                                if (count($ids) === 0) {
                                    throw new Exception('No security key registrations found for this user!');
                                }
                        
                                $getArgs = $WebAuthn->getGetArgs($ids, 20, 1, 1, 1, 1, 0);
                        
                                // save challange to session. you have to deliver it to processGet later.
                                $_SESSION['challenge'] = $WebAuthn->getChallenge();

                                header('Content-Type: application/json');
                                die(json_encode($getArgs));
                                break;
                        case "processCreate":
                                $clientDataJSON = base64_decode($post->clientDataJSON);
                                $attestationObject = base64_decode($post->attestationObject);
                                $challenge = $_SESSION['challenge'];

                                // processCreate returns data to be stored for future logins.
                                $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, 0, false, false);

                                unset($_SESSION['challenge']); // disgard challenge array from session file, no longer needed
                                session_destroy();

                                $db->query("INSERT INTO `securityKeys` (`account`, `credentialId`, `credentialPublicKey`) VALUES (?, ?, ?)", [$account->id, base64_encode($data->credentialId), $data->credentialPublicKey]);
                                $db->query("UPDATE `accounts` SET `securityKey` = 1 WHERE `id` = ?", [$account->id]);

                                $return = new stdClass();
                                $return->success = true;
                                $return->msg = 'registration success.';

                                header('Content-Type: application/json');
                                die(json_encode($return));
                                break;
                        case "processGet":
                                $clientDataJSON = base64_decode($post->clientDataJSON);
                                $authenticatorData = base64_decode($post->authenticatorData);
                                $signature = base64_decode($post->signature);
                                $userHandle = base64_decode($post->userHandle);
                                $id = base64_decode($post->id);
                                $challenge = $_SESSION['challenge'];
                                $credentialPublicKey = null;
                        
                                // looking up correspondending public key of the credential id
                                // you should also validate that only ids of the given user name
                                // are taken for the login.
                                        
                                $query = $db->query("SELECT * FROM `securityKeys` WHERE `account` = ?", [$account->id]);
                                        if ($query->num_rows > 0) {
                                                while ($row = mysqli_fetch_array($query->result)) {
                                                        if(base64_decode($row["credentialId"]) === $id) {
                                                                $credentialPublicKey = $row["credentialPublicKey"];
                                                                break;
                                                        }
                                                }
                                        }
                        
                                if ($credentialPublicKey === null) {
                                    throw new Exception('This security key wasn\'t found!');
                                }
                        
                                // process the get request. throws WebAuthnException if it fails
                                $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, null, 0);
                                        
                                unset($_SESSION['challenge']); // disgard challenge array from session file, no longer needed
                                session_destroy();

                                $session = new Session("accessToken");
                                $session->start(array("id" => (int) $account->id, "auth" => true, "mfa" => null, "email" => $account->email));
                        
                                $return = new stdClass();
                                $return->success = true;
                        
                                header('Content-Type: application/json');
                                die(json_encode($return));
                                break;
                        default:
                                $response = new Response(status: 404, error: "Not found", env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
                                $response->send();
                                break;
                }
                break;
        case "/api/v1/auth/webauthn?fn=getCreateArgs":
        case "/api/v1/auth/webauthn?fn=getGetArgs":
        case "/api/v1/auth/webauthn?fn=processCreate":
        case "/api/v1/auth/webauthn?fn=processGet":
                $session = new Session(sessionName: "accessToken");
                $account = $session->get();

                require_once '../src/WebAuthn.php';
                /*
                 * Copyright (C) 2022 Lukas Buchs
                 * license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
                 * 
                */
                $fn = filter_input(INPUT_GET, 'fn');
                $post = trim(file_get_contents('php://input'));
                $userId = bin2hex(openssl_random_pseudo_bytes(10));
                if ($post) {
                        $post = json_decode($post);
                }
                $formats = array();
                $formats[] = 'none';

                $rpId = $_SERVER['HTTP_HOST'];

                // cross-platform: true, if type internal is not allowed
                //                 false, if only internal is allowed
                //                 null, if internal and cross-platform is allowed
                $crossPlatformAttachment = null;
                
                // new Instance of the server library.
                // make sure that $rpId is the domain name.
                $WebAuthn = new lbuchs\WebAuthn\WebAuthn('jwt-webauthn-php', $rpId, $formats);

                session_start(); // for saving challenge temporarily. Redis could be used instead.

                $db = new Database("localhost", "root", "", "jwt-webauthn-php");

                switch($fn) {
                        case "getCreateArgs":
                                $createArgs = $WebAuthn->getCreateArgs($userId, $account->id, "", 20, 0, "discouraged", $crossPlatformAttachment);

                                // save challange to session. you have to deliver it to processGet later.
                                $_SESSION['challenge'] = $WebAuthn->getChallenge();

                                header('Content-Type: application/json');
                                die(json_encode($createArgs));
                                break;
                        case "getGetArgs":
                                $ids = array();

                                // load registrations from session stored there by processCreate.

                                $query = $db->query("SELECT * FROM `securityKeys` WHERE `account` = ?", [$account->id]);
                                        if ($query->num_rows > 0) {
                                                while ($row = mysqli_fetch_array($query->result)) {
                                                        $ids[] = base64_decode($row["credentialId"]);
                                                }
                                        }
                                
                                if (count($ids) === 0) {
                                    throw new Exception('No security key registrations found for this user!');
                                }
                        
                                $getArgs = $WebAuthn->getGetArgs($ids, 20, 1, 1, 1, 1, 0);
                        
                                // save challange to session. you have to deliver it to processGet later.
                                $_SESSION['challenge'] = $WebAuthn->getChallenge();

                                header('Content-Type: application/json');
                                die(json_encode($getArgs));
                                break;
                        case "processCreate":
                                $clientDataJSON = base64_decode($post->clientDataJSON);
                                $attestationObject = base64_decode($post->attestationObject);
                                $challenge = $_SESSION['challenge'];

                                // processCreate returns data to be stored for future logins.
                                $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, 0, false, false);

                                unset($_SESSION['challenge']); // disgard challenge array from session file, no longer needed
                                session_destroy();

                                $db->query("INSERT INTO `securityKeys` (`account`, `credentialId`, `credentialPublicKey`) VALUES (?, ?, ?)", [$account->id, base64_encode($data->credentialId), $data->credentialPublicKey]);
                                $db->query("UPDATE `accounts` SET `securityKey` = 1 WHERE `id` = ?", [$account->id]);

                                $return = new stdClass();
                                $return->success = true;
                                $return->msg = 'registration success.';

                                header('Content-Type: application/json');
                                die(json_encode($return));
                                break;
                        case "processGet":
                                $clientDataJSON = base64_decode($post->clientDataJSON);
                                $authenticatorData = base64_decode($post->authenticatorData);
                                $signature = base64_decode($post->signature);
                                $userHandle = base64_decode($post->userHandle);
                                $id = base64_decode($post->id);
                                $challenge = $_SESSION['challenge'];
                                $credentialPublicKey = null;
                        
                                // looking up correspondending public key of the credential id
                                // you should also validate that only ids of the given user name
                                // are taken for the login.
                                        
                                $query = $db->query("SELECT * FROM `securityKeys` WHERE `account` = ?", [$account->id]);
                                        if ($query->num_rows > 0) {
                                                while ($row = mysqli_fetch_array($query->result)) {
                                                        if(base64_decode($row["credentialId"]) === $id) {
                                                                $credentialPublicKey = $row["credentialPublicKey"];
                                                                break;
                                                        }
                                                }
                                        }
                        
                                if ($credentialPublicKey === null) {
                                    throw new Exception('This security key wasn\'t found!');
                                }
                        
                                // process the get request. throws WebAuthnException if it fails
                                $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, null, 0);
                                        
                                unset($_SESSION['challenge']); // disgard challenge array from session file, no longer needed
                                session_destroy();

                                $session = new Session("accessToken");
                                $session->start(array("id" => (int) $account->id, "auth" => true, "mfa" => null, "email" => $account->email));
                        
                                $return = new stdClass();
                                $return->success = true;
                        
                                header('Content-Type: application/json');
                                die(json_encode($return));
                                break;
                        default:
                                $response = new Response(status: 404, error: "Not found", env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
                                $response->send();
                                break;
                }
                break; 
        default:
                $response = new Response(status: 404, error: "Not found", env: "production", log: htmlentities($_SERVER['REQUEST_URI']));
                $response->send();
                break;
}
