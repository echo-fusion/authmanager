# AuthManager

[![CI](https://github.com/echo-fusion/authmanager/actions/workflows/ci.yml/badge.svg)](https://github.com/echo-fusion/authmanager/actions/workflows/ci.yml) [![Packagist](https://img.shields.io/packagist/v/echo-fusion/authmanager.svg)](https://packagist.org/packages/echo-fusion/authmanager) [![PHP](https://img.shields.io/badge/php-8.1%20%7C%208.2%20%7C%208.3-777bb4.svg)](https://www.php.net) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**AuthManager** handles authentication for the EchoFusion framework: who is the current user, log in, log out, and protecting routes. It supports **session** and **token** authentication from the start, chosen in configuration, and anything else you plug in.

It depends only on [echo-fusion/contracts](https://github.com/echo-fusion/contracts) and PSR interfaces. It does **not** require `sessionmanager`, `databasemanager`, an ORM or an entity class: it talks to a `SessionInterface`, a `ConnectionInterface` and a PSR-17 response factory, and the application decides what sits behind them.

```
GuardInterface            (who is the user for this request?)
 ├─ SessionGuard          stateful: keeps the user id in the session
 ├─ TokenGuard            stateless: the user owns the token sent with the request
 └─ your own guard        e.g. JWT, API signature ...

UserProviderInterface     (where do users come from?)
 ├─ DatabaseUserProvider  any ConnectionInterface: PDO, Doctrine DBAL ...
 ├─ ArrayUserProvider     config / tests
 └─ your own provider     LDAP, an ORM, a remote API ...
```

> Part of [EchoFusion](https://github.com/echo-fusion), a modular PHP framework built from small packages.

## Installation

```bash
composer require echo-fusion/authmanager
```

## Requirements

* PHP 8.1, 8.2 or 8.3

## Configuration

```php
return [
    'default' => 'web',

    'guards' => [
        'web' => ['driver' => 'session', 'provider' => 'users', 'key' => 'auth_user'],
        'api' => ['driver' => 'token',   'provider' => 'users',
                  'header' => 'Authorization', 'scheme' => 'Bearer',   // Authorization: Bearer <token>
                  'query' => 'api_token'],                              // optional ?api_token=<token>
        'internal' => ['driver' => 'token', 'provider' => 'users',
                       'header' => 'X-Api-Key', 'scheme' => null],      // bare token in a custom header
        'custom' => ['class' => MyGuard::class, 'provider' => 'users'], // new MyGuard($provider, $definition, $container)
    ],

    'providers' => [
        'users' => ['driver' => 'database', 'table' => 'users', 'id' => 'id', 'password' => 'password', 'token' => 'api_token'],
        'staff' => ['driver' => 'database', 'connection' => 'staff_db', 'table' => 'staff'],   // a named connection
        'fixed' => ['driver' => 'array', 'users' => [['id' => 1, 'email' => 'a@b.c', 'password' => '<hash>']]],
        'ldap'  => ['class' => LdapProvider::class],                    // new LdapProvider($definition, $container)
    ],

    'hasher' => ['algorithm' => 'bcrypt', 'options' => ['cost' => 12]], // or 'argon2id'

    'middleware' => [
        'authenticate' => ['guard' => 'web', 'redirect_to' => '/login'],
        'guest'        => ['guard' => 'web', 'redirect_to' => '/'],
    ],
];
```

## Usage

```php
use EchoFusion\AuthManager\AuthManager;

$auth = new AuthManager($container, $config);   // $container: any PSR-11 container, see "Requirements of the container"

$web = $auth->statefulGuard('web');

if ($web->attempt(['email' => $email, 'password' => $password])) {
    // logged in: the session id was regenerated and the user id stored
}

$web->check();      // bool
$web->guest();      // bool
$web->id();         // the user id, or null
$web->user();       // UserInterface or null
$web->logout();

$web->login($user); // log a user in without checking a password (e.g. right after registration)
```

`attempt()` looks the user up by every credential **except** `password` (so `['email' => ...]`, or `['email' => ..., 'active' => 1]`), then checks the password against the stored hash.

### Register a user

```php
/** @var \EchoFusion\AuthManager\Users\DatabaseUserProvider $users */
$users = $auth->provider('users');
$user = $users->create(['name' => 'Ann', 'email' => 'ann@example.com', 'password' => $plainPassword]);   // the password is hashed
$web->login($user);
```

### API tokens

```php
$api = $auth->guard('api');      // reads the token from the request, so give it one:
$api->setRequest($request);      // the middleware below does this for you
$api->user();
```

Tokens are stored as a **SHA-256 hash**, never in plain text. Create one like this:

```php
$token = bin2hex(random_bytes(32));
$connection->execute('UPDATE users SET api_token = ? WHERE id = ?', [hash('sha256', $token), $userId]);
// give $token to the client once; it cannot be recovered from the database
```

### Middleware (PSR-15)

```php
use EchoFusion\AuthManager\Middleware\AuthenticateMiddleware;
use EchoFusion\AuthManager\Middleware\GuestMiddleware;

new AuthenticateMiddleware($auth, $responseFactory, 'web', '/login');   // guard name, redirect target
new GuestMiddleware($auth, $responseFactory, 'web', '/');
```

* `AuthenticateMiddleware` lets authenticated requests through and adds the request attributes `auth.user` and `auth.guard`. Otherwise browsers are redirected to the given URL, and API clients (`Accept: application/json`, `X-Requested-With: XMLHttpRequest`, or no redirect configured) get a `401` JSON response.
* `GuestMiddleware` is for pages like login: logged-in browsers are redirected, API clients get a `403`.

Neither one ever calls `header()` or `exit()`; they return PSR-7 responses.

## Security notes

* Passwords use `password_hash` (bcrypt cost 12 by default, or argon2id). bcrypt only reads the first 72 bytes, so longer passwords are **rejected** instead of silently truncated.
* The session id is regenerated on login and logout (session fixation).
* A user that has been deleted since the last request is dropped from the session.
* The database provider validates table and column names and binds every value; lookups by credentials never compare the password in SQL (the old echo-php code did).
* Token lookups use the hash of the token. A leaked database does not leak working tokens.

## Requirements of the container

`AuthManager` receives a PSR-11 container and fetches what a configured guard needs, only when it is first used:

| Needed for | Container entry |
| --- | --- |
| a `session` guard | `EchoFusion\Contracts\SessionManager\SessionInterface` |
| a `database` provider | `EchoFusion\Contracts\DatabaseManager\ConnectionInterface` (or `DatabaseManagerInterface` when the provider names a `connection`) |
| the middleware (via the service provider) | `Psr\Http\Message\ResponseFactoryInterface` |

## Service provider

`EchoFusion\AuthManager\Providers\AuthManagerProvider` registers `AuthManagerInterface`, `GuardInterface` (the default guard), `PasswordHasherInterface`, `AuthenticateMiddleware` and `GuestMiddleware`, and configures the manager from the `auth` section of your configuration on `boot()`.

## Your own guard or provider

Implement `GuardInterface` (or `StatefulGuardInterface`) or `UserProviderInterface` from the contracts and reference the class with `'class'`. A guard that needs the request (like the token guard) can also implement `EchoFusion\AuthManager\Guards\RequestAwareGuardInterface`; the middleware hands it the request.

## Testing

```bash
composer test
```

## Credits

- [Amir Shadanfar](https://github.com/amir-shadanfar)

## License

The MIT License (MIT). Please see [LICENSE](LICENSE) for more information.
