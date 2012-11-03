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


  public function __construct(array $handlers, array $options = array())
  {

    $this->handlers = array(
      'authorize' => Utils::get($handlers, 'authorize'),
      'process' => Utils::get($handlers, 'process')
    );

    $internal_handlers = array(
      'authorize' => array($this, 'authorize'),
    );

    parent::__construct($internal_handlers, $options);

  }


  public function receive()
  {

    $this->ssl = isset($_SERVER["HTTPS"]) && strtolower($_SERVER["HTTPS"]) !== "off";

    $options = array(
      'strict' => true,
      'public' => false,
    );

    Utils::config($this->options, $options);

    parent::receive();
    $this->input =  @file_get_contents('php://input');
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
  * Note that a content-type header may be overwritten due to encoding
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

    $enc = $this->getRequestXHeader('enc');
    $error = null;

    if (!$this->ssl)
    {

      if (!$enc)
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

    # if we have been encoded, we will have replaced the Content-Type header
    if ($enc)
    {

      if ($content = $this->getRequestXHeader('content-type'))
      {
        $_SERVER['CONTENT_TYPE'] = $content;
      }

    }

    return Utils::callHandler($this->handlers, 'authorize', array($this));

  }


  private function checkEnc(&$enc, &$error)
  {

    $enc = $this->getRequestXHeader('enc');

    if (!$this->ssl && !$enc)
    {
      $error = 'Required x-header is missing: enc';

      return;
    }

    if (!$this->ssl)
    {

      if (!$enc = $this->getRequestXHeader('enc'))
      {
        $error = 'Required x-header is missing: enc';
      }
      elseif (strpos($enc, Encoder::ENC_AES) === false)
      {
        $error = 'Required x-header enc is missing value: ' . Encoder::ENC_AES;
      }

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
