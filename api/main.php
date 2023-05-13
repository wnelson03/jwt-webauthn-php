<?php
require_once 'components/Jwt.php';
require_once 'components/Key.php';

class Session {
        public function __construct(
                public string $sessionName,
        ) {}

        public function get() {
                if(!isset($_COOKIE[$this->sessionName]))
                        throw new Exception("Access token cookie not set");

                try {
                        $session = Firebase\JWT\JWT::decode($_COOKIE[$this->sessionName], new Firebase\JWT\Key('yWvati2Z94ZV6XFaSwC7gqdsabtTYHqMnzWB7o58AvCXHkheS8ANfHLKTTwXE9cXHg7GH2bSb9q95Lo2He9XDWtqDBwJzvKFbX8ymeLPkhFQkJxF8GDbmpRUfeXctiLi', 'HS256'));
                }
                catch (Exception) {
                        setcookie('accessToken', '', 0, '/'); // delete cookie on browser
                        throw new Exception("Failed to decode access token");
                }

                return new Account(id: (int) $session->id , auth: (bool) $session->auth, mfa: $session->mfa, email: $session->email);
        }
        public function set($sessionValue) {
                setcookie($this->sessionName, $sessionValue, time()+86400, "/");
                return;
        }
        public function start($payload) {
                $encoded = Firebase\JWT\JWT::encode($payload, 'yWvati2Z94ZV6XFaSwC7gqdsabtTYHqMnzWB7o58AvCXHkheS8ANfHLKTTwXE9cXHg7GH2bSb9q95Lo2He9XDWtqDBwJzvKFbX8ymeLPkhFQkJxF8GDbmpRUfeXctiLi', 'HS256');
                $this->set($encoded);
        }
}

class Account {
        public function __construct(
                public ?int $id  = null,
                public ?bool $auth  = null,
                public ?string $mfa = null,
                public ?string $email = null,
        ) {}

        public function isAuthenticated() {
                return $this->auth;
        }

        public function register($password) {
                if(empty($this->email))
                        throw new Exception("Email has not been specified");

                if(empty($password))
                        throw new Exception("Password has not been specified");

                $db = new Database("localhost", "root", "", "jwt-webauthn-php");
                $query = $db->query("SELECT 1 FROM `accounts` WHERE `email` = ?", [$this->email]);
                if ($query->num_rows >= 1) {
                        throw new Exception("Email already taken!");
                }

                $passHashed = password_hash($password, PASSWORD_BCRYPT);

                $query = $db->query("INSERT INTO `accounts` (`email`, `password`) VALUES (?, ?)", [$this->email, $passHashed]);
                if ($query->affected_rows > 0) {
                        $session = new Session("accessToken");
                        $session->start(array("id" => (int) $query->insert_id, "auth" => true, "mfa" => null, "email" => $this->email));
                        return true;
                }
                else {
                        throw new Exception("Failed to register account");
                }
        }

        public function login($password) {
                if(empty($this->email))
                        throw new Exception("Email has not been specified");

                if(empty($password))
                        throw new Exception("Password has not been specified");

                $db = new Database("localhost", "root", "", "jwt-webauthn-php");
                $query = $db->query("SELECT * FROM `accounts` WHERE `email` = ?", [$this->email]);
                if ($query->num_rows < 1) {
                        throw new Exception("Email not found!");
                }

                while ($row = mysqli_fetch_array($query->result)) {
                        $id = $row['id'];
                        $passHashed = $row['password'];
                        $securityKey = $row['securityKey'];
                }

                if (password_verify($password, $passHashed)) {
                        $session = new Session("accessToken");
                        $session->start(array("id" => (int) $id, "auth" => !$securityKey, "mfa" => $securityKey ? "webauthn" : null, "email" => $this->email));
                }
                else {
                        throw new Exception("Password is invalid");
                }

                if($securityKey)
                        throw new Exception("Security key required.");

                return true;
        }
}

class Database {
        private $connection;

        public function __construct($databaseHost, $databaseUsername, $databasePassword, $databaseName) {
                $this->connection = new mysqli($databaseHost, $databaseUsername, $databasePassword, $databaseName);

                if(!$this->connection)
                        throw new Exception($this->connection->connect_error);
        }

        public function __destruct() {
                $this->connection->close();
        }

        public function query($query, $args = [], $types = null) {
	        if (is_null($types) && !empty($args))
	        	$types = str_repeat('s', count($args)); // unless otherwise specified, set type to string

	        $stmt = $this->connection->prepare($query);

	        if (!$stmt)
                        throw new Exception($this->connection->error);

	        if (str_contains($query, "?"))
	        	$stmt->bind_param($types, ...$args);

	        $stmt->execute();

	        $query = new \stdClass();
	        $query->result = $stmt->get_result();
	        $query->num_rows = $query->result->num_rows;
	        $query->affected_rows = $stmt->affected_rows;
                $query->insert_id = $stmt->insert_id;

	        $stmt->close();

	        return $query;
        }
}

class Response {
        public function __construct(
                public ?int $status = null,
                public ?array $data = null,
                public ?string $error = null,
                public ?string $message = null,
                public ?string $env = null,
                public ?string $log = null,
        ) {}

        public function send() {
                header("Content-type: application/json");
                die(json_encode(array("status" => (int) $this->status, "data" => $this->data, "error" => $this->error, "message" => $this->message, "env" => $this->env, "log" => $this->log)));
        }
}