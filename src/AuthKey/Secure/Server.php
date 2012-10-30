<?php
namespace AuthKey\Secure;

use AuthKey\Utils;


class Server extends \AuthKey\Transport\Server
{

  public $input = '';

  /** @var Encoder */
  private $encoder = null;
  private $ssl = false;
  private $handlers = array();


  public function __construct(array $handlers)
  {

    $this->handlers = array(
      'authorize' => Utils::get($handlers, 'authorize'),
      'process' => Utils::get($handlers, 'process')
    );

    $internal_handlers = array(
      'authorize' => array($this, 'authorize'),
    );

    parent::__construct($internal_handlers);

  }


  public function receive()
  {

    $this->ssl = isset($_SERVER["HTTPS"]) && strtolower($_SERVER["HTTPS"]) !== "off";

    $options = array(
      'strict' => true,
      'public' => false,
    );

    $this->config($options);

    $this->input = parent::receive();
    $this->inputDecode();

    if (!empty($this->handlers['process']))
    {
      Utils::callHandler($this->handlers, 'process', array($this));
    }
    else
    {
      return $this->input;
    }

  }


  /**
  * Sets the content and (optional headers) for the response.
  * Note that acontent-type header may be overwritten due to encoding
  *
  * @param string $content
  * @param array $headers
  */
  public function reply($content, $headers = array())
  {

    $headers = (array) $headers;
    $this->outputEncode($content, $headers);
    parent::reply($content, $headers);

  }


  public function authorize(Server $Server)
  {

    $error = null;

    if (!$this->ssl)
    {

      if (!$enc = $Server->getRequestXHeader('enc'))
      {
        $error = 'Required x-header is missing: enc';
      }
      elseif (strpos($enc, Encoder::ENC_AES) === false)
      {
        $error = 'Required x-header enc is missing value: ' . Encoder::ENC_AES;
      }

    }

    if ($error)
    {

      return array(
        'errorResponse' => 400,
        'errorMsg' => $error,
        'errorCode' => 'MissingSecurityHeader',
      );

    }
    else
    {
      return Utils::callHandler($this->handlers, 'authorize', array($this));
    }

  }


  private function inputDecode()
  {

    $this->encoder = new Encoder($this->accountKey, $this->ssl);
    $enc = $this->getRequestXHeader('enc');

    if (!$this->encoder->decode($this->input, $enc))
    {
      throw new \Exception('Decryption failed');
    }

  }


  private function outputEncode(&$content, array &$headers)
  {

    if (!is_string($content))
    {
      throw new \Exception('Invalid content: ' . gettype($content));
    }

    $enc = '';

    if (!$this->encoder->encode($content, $enc))
    {
      throw new \Exception('Encryption failed');
    }

    if ($enc)
    {
      $this->setXHeaderOut('enc', $enc);
      $headers[] = 'Content-Type: application/octet-stream';
    }

  }


}