
# PhpSocket

A WebSocket server implemented in PHP language.

## Instalation

Add the source code to the project via Composer:

	composer require radoid/phpsocket

Then, make sure the Composer's auto-loading mechanism is being used in your project:

	<?php
	require '../vendor/autoload.php';

## Starting and Stopping the Server

The server is instantiated from the `PhpSocket` class. Method `listen()` will start listening for incoming connections on the desired port:

	use PhpSocket\PhpSocket;

	$port = 1444;
	$server = new PhpSocket;
	$server->listen($port);

The listening can be stopped with `stop()` method. You also may find it practical to stop it in shell by pressing Ctrl+C (^C).

## Implementing Custom Functionality

Your custom logic should be implemented by extending the `PhpSocket` class. It has a number of methods, corresponding to events, that can be overriden:

| Method        | Event                                                              |
|---------------|--------------------------------------------------------------------|
| `onreceive()` | New data has been received on a not-yet-upgraded (HTTP) connection |
| `onupgrade()` | An upgrade request, that should be either allowed or declined      |
| `onopen()`    | A connection has been upgraded                                     |
| `onmessage()` | New data has been received on an upgraded (WebSocket) connection   |
| `ontimeout()` | The socket has timed out, ie. had no incoming messages for an hour |
| `onclose()`   | A connection has been terminated                                   |  

During the lifetime of a connection, the following methods are available:

| Method         | Purpose                                   |
|----------------|-------------------------------------------|
| `send()`       | Sends a message/data through a connection |
| `disconnect()` | Terminates a connection                   |
| `log()`        | Outputs arbitrary text                    |
