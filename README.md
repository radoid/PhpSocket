
# PhpSocket

A WebSocket server implemented in PHP language.

## Instalation

Add the source code to the project via Composer:

	composer require radoid/phpsocket

Then, make sure the Composer's auto-loading mechanism is being used in your project:

	<?php
	require '../vendor/autoload.php';

## Starting and stopping the server

The server is instantiated from the `PhpSocket` class. Method `listen()` will start listening for incoming connections on the desired port:

	use PhpSocket\PhpSocket;

	$port = 1444;
	$server = new PhpSocket;
	$server->listen($port);


The listening can be stopped with `stop()` method. You also may find it practical to stop it in shell by pressing Ctrl+C (^C).

## Implementing custom functionality

Your custom logic should be implemented by extending the `PhpSocket` class. It has a number of methods, corresponding to events, that can be overriden:

| Method        | Event                                                              |
|---------------|--------------------------------------------------------------------|
| `onreceive()` | New data has been received on a not-yet-upgraded (HTTP) connection |
| `authorize()` | An upgrade request should be authorized                            |
| `onopen()`    | A connection has been authorized/upgraded                          |
| `onmessage()` | New data has been received on an upgraded (WebSocket) connection   |
| `onclose()`   | A connection has been terminated                                   |  

