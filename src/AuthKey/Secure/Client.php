<?php
namespace AuthKey\Secure;

use AuthKey\Utils;


class Client extends \AuthKey\Transport\Client
{


  /** @var Encoder */
  private $encoder = null;
  private $ssl = false;


  public function send($method, $url, $data)
  {

    $this->ssl = stripos($url, 'https://') !== false;

    if (!$this->requestEncode($data))
    {
      return false;
    }

    $this->setOption('strict', true);

    $method = $data ? 'POST' : 'GET';

    if (!parent::send($method, $url, $data))
    {
      $this->setErrorData();
      return false;
    }

    return $this->responseDecode();

  }


  private function requestEncode(&$content)
  {

    if (!is_string($content))
    {
      $this->setError(static::ERR_INTERNAL, 'Invalid content: ' . gettype($content));
      return false;
    }

    $this->encoder = new Encoder(Utils::get($this->account, 'key'), $this->ssl);

    $enc = '';

    if (!$this->encoder->encode($content, $enc))
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


  private function setErrorData()
  {

    if ($this->errorCode === static::ERR_REQUEST && $this->output)
    {

      if ($ar = @json_decode($this->output, true))
      {

        if (Utils::get($ar, 'code') && Utils::get($ar, 'message'))
        {
          $this->error = $this->errorCode . ': ' . $this->output;
        }

      }

    }

  }


}

