<?php
namespace AuthKey\Secure;

use AuthKey\Utils;


class Encoder
{

  private $td = null;
  private $secret = '';
  private $ivSize = 0;
  private $keySize = 0;
  private $ssl = false;

  const ENC_AES = 'aes';
  const ENC_GZIP = 'gzip';
  const GZIP_MIN = 300;


  public function __construct($secret, $ssl)
  {

    $this->secret = $secret;
    $this->td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
    $this->ivSize = mcrypt_enc_get_iv_size($this->td);
    $this->keySize = 32;
    $this->ssl = $ssl;

  }


  public function decode(&$data, $enc)
  {

    if ($data)
    {

      if (!$this->ssl && $this->encHas($enc, static::ENC_AES))
      {

        $iv = substr($data, 0, $this->ivSize);
        $nonce = substr($data, $this->ivSize, $this->ivSize);

        if (!$this->init($nonce, $iv))
        {

          return;
        }
        else
        {
          $data = rtrim(mdecrypt_generic($this->td, substr($data, $this->ivSize * 2)), "\0");
          mcrypt_generic_deinit($this->td);
        }

      }

      if ($this->encHas($enc, static::ENC_GZIP))
      {
        $data = $this->gzDecodeEx($data);
      }

    }

    return true;

  }


  public function encode(&$data, &$enc)
  {

    $enc = '';

    if ($data)
    {

      if (strlen($data) > static::GZIP_MIN)
      {
        $data = gzencode($data, 9);
        $enc = Utils::addCsv($enc, static::ENC_GZIP);
      }

      if ($this->ssl)
      {

        return true;
      }

      $iv = $this->getRandom();
      $nonce = $this->getRandom();

      if (!$this->init($nonce, $iv))
      {

        return;
      }
      else
      {
        $data = $iv . $nonce . mcrypt_generic($this->td, $data);
        mcrypt_generic_deinit($this->td);
        $enc = Utils::addCsv($enc, static::ENC_AES);
      }

    }

    return true;

  }


  private function getRandom()
  {

    if (function_exists('openssl_random_pseudo_bytes'))
    {
      $random = openssl_random_pseudo_bytes($this->ivSize);
    }
    else
    {
      $random = mcrypt_create_iv($this->ivSize, MCRYPT_DEV_RANDOM);
    }

    return $random;

  }


  private function init($nonce, $iv)
  {

    $key = $this->getKey($nonce, $iv);

    $res = @mcrypt_generic_init($this->td, $key, $iv);

    return !($res < 0 || $res === false);

  }


  private function getKey($nonce, $iv)
  {

    $key = hash_hmac('sha256', $nonce . $this->secret . $iv, $this->secret, true);

    return $this->toSize($this->keySize, $key);

  }


  private function toSize($size, $value)
  {

    $len = strlen($value);

    if ($len > $size)
    {
      $value = substr($value, 0, $size);
    }
    elseif ($len < $size)
    {
      $value = str_pad($value, $size, "\0");
    }

    return $value;

  }


  private function encHas($enc, $type)
  {
    return strpos($enc, $type) !== false;
  }


  private function gzDecodeEx($data)
  {

    if (function_exists('gzdecode'))
    {

      return gzdecode($data);
    }

    $flags = ord(substr($data, 3, 1));
    $headerLen = 10;
    $dataLen = strlen($data);

    if ($flags & 4)
    {
      $extraLen = unpack('v' ,substr($data, 10, 2));
      $extraLen = $extraLen[1];
      $headerLen += 2 + $extraLen;
    }

    $tests[] = 8; // filename
    $tests[] = 16; // comment

    while ($tests && $dataLen > $headerLen)
    {

      if ($flags & $tests[0])
      {
        $headerLen += strpos($data, chr(0), $headerLen) + 1;
      }

      array_shift($tests);

    }

    if ($flags & 2) // CRC at end of headers
    {
      $headerLen += 2;
    }

    if ($dataLen > $headerLen)
    {

      return gzinflate(substr($data, $headerLen));
    }
    else
    {

      return $data;
    }

  }


}
