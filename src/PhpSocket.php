<?php
namespace PhpSocket;

use Throwable;

/**
 * Implements a WebSocket server
 */
class PhpSocket {

	/**
	 * Client socket streams
	 * @var resource[]
	 */
	private $streams;

	/**
	 * Indicates whether connections are upgraded from HTTP to WebSocket
	 * @var bool[]
	 */
	private $upgrades;

	/**
	 * Connections' raw data buffers
	 * @var string[]
	 */
	private $buffers;

	/**
	 * Connections' message storages
	 * @var string[]
	 */
	private $messages;

	/**
	 * Next auto-incrementing connection ID
	 * @var int
	 */
	private $nextId;

	/**
	 * Current priority level for logging info
	 * @var int
	 */
	protected $logLevel;


	/**
	 * The constructor
	 */
	public function __construct(int $logLevel = 0) {
		$this->logLevel = $logLevel;
	}

	/**
	 * Starts listening on a given port
	 */
	public function listen(int $port, ?string $cert = null): void {
		if ($cert) {
			$certInfo = openssl_x509_parse(file_get_contents($cert))
				or die("Cannot use certifikate $cert.\n");
			if ($certInfo['validTo_time_t'] < time())
				die("Certificate $cert has expired.\n");
		}

		$url = ($cert ? 'ssl://':'') . "0.0.0.0:$port";
		$context = stream_context_create(['ssl' => [
				'local_cert' => $cert,
				'verify_peer' => false,
				'verify_peer_name' => false,
				'allow_self_signed' => true,
		]]);
		ini_set('default_socket_timeout', 3);
		$master = stream_socket_server($url, $errno, $errstr, STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $context)
			or die("stream_socket_server: $errstr.\n");
		$this->log("Listening on $url at ".date('Y-m-d H:i:s')."...\n", 0);

		$this->streams = [$master];
		$this->upgrades = $this->buffers = $this->messages = [];
		$this->nextId = 1;
		$null = NULL;

		try {
			while ($this->streams) {
				$this->log('--- '.date('D H:i:s').' -- '.count($this->streams)." sockets ---\n");
				$changed = $this->streams;
				$count = stream_select($changed, $null, $null, 3600, 0);
				if ($count > 0) {
					foreach ($changed as $id => $stream)
						if ($this->streams)
							if ($stream == $master)
								$this->accept($stream);
							elseif (feof($stream))
								$this->disconnect($id);
							elseif ($this->upgrades[$id])
								$this->receiveUpgraded($id, $stream);
							else
								$this->receive($id, $stream);
				} elseif ($count === 0)
					$this->ontimeout();
				else {
					$this->log("stream_select: fail\n", 0);
					break;
				}
			}
		} catch (Throwable $e) {
			$this->log($e->getMessage()."\n" . $e->getTraceAsString()."\n", 0);
		}

		$this->log('Stopped at '.date('Y-m-d H:i:s').".\n", 0);
	}

	/**
	 * Stops listening
	 */
	public function stop(): bool {
		foreach ($this->streams as $id => $stream)
			if ($id)
				$this->disconnect($id);
			else
				$isSuccess = stream_socket_shutdown($stream,  STREAM_SHUT_RDWR);
		$this->streams = [];

		return $isSuccess ?? false;
	}

	/**
	 * Accepts a new connection
	 * @param resource $master The master socket stream
	 */
	private function accept($master): void {
		if (($stream = stream_socket_accept($master, 3, $ipaddr))) {
			$id = $this->nextId++;
			$this->streams[$id] = $stream;
			$this->upgrades[$id] = false;
			$this->buffers[$id] = $this->messages[$id] = '';
		} else
			$this->log("stream_socket_accept ($ipaddr): fail\n", 0);
	}

	/**
	 * Receives data available on a stream that is not yet upgraded
	 * @param resource $stream
	 */
	private function receive(int $id, $stream): void {
		$message = trim(fread($stream, 8192));
		[$protocol, $uri, $headers, $body, $cookies] = $this->parseRequest($message);
		$ipaddr = stream_socket_get_name($stream, true);

		if (($response = $this->handshake($protocol, $headers))) {
			if (fwrite($stream, $response)) {
				if ($this->onupgrade($id, $uri, $headers, $cookies, $ipaddr) !== false) {
					$this->upgrades[$id] = true;
					$this->onopen($id);
				} else
					$this->disconnect($id);
			} else {
				$this->log("Failed to send upgrade packet.\n", 0);
				$this->disconnect($id);
			}
		} else
			$this->onreceive($stream, $message);
	}

	/**
	 * Receives data available on a stream that has been upgraded
	 * @param resource $stream
	 */
	private function receiveUpgraded(int $id, $stream): void {
		//$client = $this->clients[$id];
		//$isTracked = false;
		$buffer = &$this->buffers[$id];
		$message = &$this->messages[$id];
		//if ($isTracked)
		//	$this->log("$client->username -> $client->username2:", 0);

		$blob = fread($stream, 8192);

		if ($blob !== false && $blob !== '') {
			$buffer .= $blob;
			//if ($isTracked)
			//	$this->log('+'.strlen($buffer).'/'.($this->getFrameSize($buffer) ?: '?').' '.bin2hex($blob), 0);
			while (($frameSize = $this->getFrameSize($buffer)) && strlen($buffer) >= $frameSize) {
				$frame = substr($buffer, 0, $frameSize);
				$buffer = substr($buffer, $frameSize);

				$payload = $this->unframe($frame, $fin, $opcode, $length);
				//if ($isTracked)
				//	$this->log(" $fin $opcode $length", 0);
				$message .= $payload;

				if ($fin) {
					if ($opcode == 0 || $opcode == 1) {
						//if ($isTracked)
						//	$this->log(" $message", 0);
						$this->onmessage($id, $message);
					}
					elseif ($opcode == 8)
						$this->disconnect($id);
					elseif ($opcode == 9)
						fwrite($stream, $this->frame($message, 10));
					elseif ($opcode == 10)
						;
					else
						$this->log(" Unknown opcode $opcode", 0);
					$message = '';
				}
			}
			//if ($isTracked)
			//	$this->log("\n", 0);
		} else {
			$this->log("Disconnected\n");
			$this->disconnect($id);
		}
	}

	/**
	 * Fires when there is a new message on a stream that is not yet upgraded
	 * @param resource $stream
	 */
	protected function onreceive($stream, string $message): void {}

	/**
	 * Checks whether the connection is made by a valid user
	 */
	protected function onupgrade(int $id, string $uri, array $headers, array $cookies, string $ipaddr): bool { return true; }

	/**
	 * Fires when there are no connections for a long enough time that `stream_select` times out
	 */
	protected function ontimeout(): void {}

	/**
	 * Fires when a message/data arrives
	 */
	protected function onmessage(int $id, string $message): void {}

	/**
	 * Fires when a connection is authorised
	 */
	protected function onopen(int $id): void {}

	/**
	 * Fires when a connection is closed
	 */
	protected function onclose(int $id): void {}

	/**
	 * Sends a message/data through a connection
	 */
	protected function send(int $id, $message): void {
		if ($id > 0 && $this->streams[$id]) {
			$json = (is_string($message) ? $message : json_encode($message));
			$blob = $this->frame($json, 1);
			if (fwrite($this->streams[$id], $blob) === false)
				$this->disconnect($id);
		}
	}

	/**
	 * Terminates a connection
	 */
	protected function disconnect(int $id): void {
		if ($id > 0 && $this->streams[$id]) {
			fclose($this->streams[$id]);
			if ($this->upgrades[$id])
				$this->onclose($id);
			unset($this->streams[$id], $this->upgrades[$id], $this->buffers[$id], $this->messages[$id]);
		}
	}

	/**
	 * Constructs a WebSocket frame for a message/data and desired opcode
	 */
	private function frame(string $message, int $opcode): string {
		$b1 = 0x80 | ($opcode & 0x0f);
		$length = strlen($message);
		if ($length < 126)
			$header = pack('CC', $b1, $length);
		elseif ($length < 65536)
			$header = pack('CCn', $b1, 126, $length);
		else
			$header = pack('CCNN', $b1, 127, 0, $length);
		return $header.$message;
	}

	/**
	 * Determines the size of a given WebSocket frame
	 */
	private function getFrameSize(string $blob): ?int {
		$blobLength = strlen($blob);
		if ($blobLength > 0) {
			$length = ord($blob[1]) & 127;
			if ($length < 126)
				return 6 + $length;
			elseif ($length == 126 && $blobLength >= 4)
				return 8 + (ord($blob[2])<<8) + ord($blob[3]);
			elseif ($length == 127 && $blobLength >= 10)
				return 14 + (ord($blob[6])<<24) + (ord($blob[7])<<16) + (ord($blob[8])<<8) + ord($blob[9]);
		}
		return null;
	}

	/**
	 * Unpacks the content of a WebSocket frame
	 */
	private function unframe(string $blob, ?int &$fin, ?int &$opcode, ?int &$length): string {
		$fin = ord($blob[0]) >> 7;
		$opcode = ord($blob[0]) & 15;
		$length = ord($blob[1]) & 127;
		if ($length == 126) {
			$maskPos = 4;
			$dataPos = 8;
		} elseif ($length == 127) {
			$maskPos = 10;
			$dataPos = 14;
		} else {
			$maskPos = 2;
			$dataPos = 6;
		}
		for ($unmasked = '', $i = 0, $dataLen = strlen($blob) - $dataPos; $i < $dataLen; ++$i)
			$unmasked .= $blob[$dataPos+$i] ^ $blob[$maskPos + ($i % 4)];
		return $unmasked;
	}

	/**
	 * Parses the client's initial HTTP GET request
	 */
	private function parseRequest(string $message): ?array {
		$lines = explode("\n", trim($message));
		if (!preg_match('~^GET (\S+) (\S+)~', $lines[0], $m))
			return null;
		[, $uri, $protocol] = $m;
		$headers = $cookies = [];
		$body = '';
		foreach ($lines as $line)
			if (preg_match('~^(\S+): (.*?)\s*$~', $line, $m)) {
				if ($m[1] == 'Cookie') {
					foreach (explode('; ', $m[2]) as $cookie)
						if (list($key, $value) = explode('=', $cookie))
							$cookies[$key] = $value;
				} else
					$headers[$m[1]] = $m[2];
			} else
				$body = trim($line, "\r");

		return [$protocol, $uri ?? null, $headers, $body, $cookies];
	}

	/**
	 * Tries to prepare an answer to the "handshake"
	 */
	private function handshake(string $protocol, array $headers): ?string {
		if (($key = $headers['Sec-WebSocket-Key'] ?? null)) {
			$answer = base64_encode(pack('H*', sha1($key.'258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
			$response = "$protocol 101 Switching Protocols\r\n".
					"Upgrade: websocket\r\n".
					"Connection: Upgrade\r\n".
					"Sec-WebSocket-Accept: $answer\r\n\r\n";
		}

		return $response ?? null;
	}

	/**
	 * Outputs arbitrary text, if above the level of priority
	 */
	protected function log(string $text, int $level = 1): void {
		if ($level <= $this->logLevel)
			echo $text;
	}

}
