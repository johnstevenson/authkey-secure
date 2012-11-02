<?php
namespace AuthKey\Secure;

use AuthKey\Utils;


class Client extends \AuthKey\Transport\Client
{


  /** @var Encoder */
  private $encoder = null;
  private $ssl = false;


  public function send($method, $url, $data = '')
  {

    $method = strtoupper($method);

    $this->ssl = stripos($url, 'https://') !== false;

    if (!$this->requestEncode($data))
    {
      return false;
    }

    $this->setStrictMode(true);

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

    if ($enc)
    {

      $this->setXHeader('enc', $enc);

      # see if a content-type header has been set
      if ($content = Utils::get($this->options['headers'], 'Content-Type'))
      {

        # and set it as an xheader if we don't already have one
        if (!$xcontent = Utils::get($this->options['xheaders'], 'content-type'))
        {
          $this->setXHeader('content-type', $content);
        }

      }

      $this->setHeader('Content-Type', 'application/octet-stream');

    }

    return true;

  }


  private function responseDecode()
  {

    $enc = Utils::get($this->xheaders, 'enc');

    if (!$this->encoder->decode($this->output, $enc))
    {
      $this->setError(static::ERR_INTERNAL, 'Decryption failed');
      return false;
    }

    if ($enc)
    {

      # see if a content-type xheader has been set
      if ($content = Utils::get($this->xheaders, 'content-type'))
      {
        # and set it as a header
        $this->headers['Content-Type'] = $content;
      }

    }

    return true;

  }


}
