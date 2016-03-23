# swoole-memcached

An asynchronous PHP memcached client base on swoole

## Installation

```
git clone git@github.com:icday/swoole-src.git
cd swoole-src
# You may need to make swoole-memcached up todate
# cd swoole-memcached; git pull; cd ..
phpize
./configure --enable-async-memcached
make && make install
```

## Classes

### swoole_memcached

Using `Swoole\\Memcached` instead of `swoole_memcached` if `swoole.use_namespace=On` is set in `php.ini`.

#### Methods

`callable` is a data type that can be called, it could be **String, Array or Closure**.

The prototypes of most callback variables are `function($err, $result)`. When error occurs, `$err` will be set to a non-empty value that describes error info. You should check the `$err` before you process the `$result` in callback function.

- `__construct(string $host, int $port)`

- `connect(callable $callback)`

- `close()`    close the connection.

- `get(string $key, string $key2, ..., callable $callback)`    `get` method can retrieve multiple values from server, `$result` will be a associative array. Arguments count must be more than 1, and the last argument must be `callback`.

- `set(string $key, string $value, int expire, callable $callback)`    The prototype of `set` is the same as `add` and `replace`. The `$result` of callback is a bool variable which means whether this operation effected the value of `$key`.

  - `set`    set the value of key anyway.

  - `add`    set the value of key if the key is not exists.

  - `replace` set the value of key if the key is exists.

- `delete(string $key, callable $callback)`    `$result` is a bool variable which means whether the deleting operation is successed.

- `incr(string $key, int $num, callable $callback)`    `$num` should be positive. `result` is the value after operation.

- `decr(string $key, int $num, callable $callback)`    `$num` should be positive. `result` is the value after operation.

## Examples

``` php
$memcached = new swoole_memcached('127.0.0.1', 11211);
$memcached->connect(function() use ($memcached) {
    echo "memcached is connected\n";

    $memcached->add('key1', 'value1', 0, function($err, $result) {
        if ($err) {
            echo "error:" . $err;
            return;
        }
        if ($result) {
            echo "add key1 success\n";
        } else {
            echo "add key1 failure. key1 is already exists.\n";
        }
    });

    $memcached->get('key2', 'key3', function($err, $result) {
        if ($err) {
            // error handle
            return;
        }
        if (!isset($result['key2'])) {
            echo "key2 is unset\n";
        } else {
            echo "value of key2 is:" . $result['key2'] . "\n";
        }

        if (!isset($result['key3'])) {
            echo "key3 is not exists.\n";
        } else {
            echo "value of key3 is:" . $result['key3'] . "\n";
        }
    });
});
```

#### Scope and disconnect

To close the connection, you can call the `close` method.

Connection will close when  `close` method be called, or the reference count of instance turn to 0 and there is not any uncallback asynchronous operation. In other word, it is never be destoryed before all asynchronous operation callback.

``` php
function testFunc() {
    $memcached = new swoole_memcached('127.0.0.1', 11211);
    $memcached->connect(function() use ($memcached) {
        echo "memcached is connected\n";

        $memcached->add('key1', 'value1', 0, function($err, $result) {
            if ($err) {
                echo "error:" . $err;
                return;
            }
            if ($result) {
                echo "add key1 success\n";
            } else {
                echo "add key1 failure. key1 is already exists.\n";
            }

            // connection will be closed after this function.
        });
    });
}
```

