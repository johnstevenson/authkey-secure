<?php
namespace AuthKey\Secure;

use AuthKey\Utils;


class Client extends \AuthKey\Transport\Client
{


  /** @var Encoder */
  private $encoder = null;
  private $ssl = false;


  public function send($url, $data)
  {

    $this->ssl = stripos($url, 'https://') !== false;

    if (!$this->requestEncode($data))
    {
      return false;
    }

    $this->setStrict(true);

    $method = $data ? 'POST' : 'GET';

    if (!parent::send($method, $url, $data))
    {
      return false;
    }

    return $this->responseDecode();

  }


  private function requestEncode(&$data)
  {

    if (!is_string($data))
    {
      $this->setError(static::ERR_INTERNAL, 'Invalid request data: ' . gettype($data));
      return false;
    }

    $this->encoder = new Encoder(Utils::get($this->account, 'key'), $this->ssl);

    $enc = '';

    if (!$this->encoder->encode($data, $enc))
    {
      $this->setError(static::ERR_INTERNAL, 'Encryption failed');
      return false;
    }

    $this->setXHeader('enc', $enc);
    $this->setHeader('Content-Type', 'application/octet-stream');

    return true;

  }


  private function responseDecode()
  {

    $enc = Utils::get($this->xheaders, 'enc');

    $res = $this->encoder->decode($this->output, $enc);

    if (!$res)
    {
      $this->setError(static::ERR_INTERNAL, 'Decryption failed');
    }

    return $res;

  }


}
