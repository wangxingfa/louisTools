<?php

namespace louistools;
use Exception;
/* 目前是对称加密算法 */

class Jwt {

    private $headers = ["alg" => "HS256", "type" => "jwt"];
    private $payloads = [];    //payload部分
    private $symmetry_key = ""; //对称加密的密钥
    private $token = "";
    private $effect_interval = 1000 * 60 * 30;

    /* 生成jw token */
    public function __construct($symmetry_key){
           if (empty($symmetry_key)) {
            throw new Exception("JWT非法操作");
            }
             $this->symmetry_key = $symmetry_key;
    }
    public function setData($payloads, $effect_interval = 1000 * 60 * 30) {
        $this->effect_interval = $effect_interval;
        $this->payloads = $payloads;
        $this->payloads["start_time"] = time();
        $this->payloads["expire_time"] = time() + $this->effect_interval;
        $this->payloads["effect_interval"] = $this->effect_interval;
       
    }

    /**
     * JWT TOKEN的生成
     * @param NULL
     * @return String
     */
    public function getToken() {
        if (empty($this->payloads)) {
            throw new Exception("JWT非法操作");
        }
        $base64header = $this->base64UrlEncode(json_encode($this->headers, JSON_UNESCAPED_UNICODE));
        $base64payload = $this->base64UrlEncode(json_encode($this->payloads, JSON_UNESCAPED_UNICODE));
        $signature = $this->signature($base64header . '.' . $base64payload, $this->symmetry_key);
        $this->token = $base64header . "." . $base64payload . "." . $signature;
        return $this->token;
    }

    /**
     * 验证token是否有效,默认验证exp,nbf,iat时间
     * @param string $token 需要验证的token
     * @return bool|Array
     */
    public function VerifyToken($token) {
        $tokens = explode('.', $token);
        if (count($tokens) != 3){
            return false;
        }
        list($base64header, $base64payload, $signature) = $tokens;
        //获取jwt算法
        $base64decodeheader = json_decode($this->base64UrlDecode($base64header), JSON_OBJECT_AS_ARRAY);
        if (!isset($base64decodeheader['alg'])||empty($base64decodeheader['alg']) || strtolower($base64decodeheader['alg'])!="hs256"){
            return false;
        }
         if (!isset($base64decodeheader['type'])||empty($base64decodeheader['type']) || strtolower($base64decodeheader['type'])!="jwt"){
            return false;
        }
        //签名验证
        if ($this->signature($base64header . '.' . $base64payload, $this->symmetry_key) !== $signature){
            return false;
        }
        $payload = json_decode($this->base64UrlDecode($base64payload), JSON_OBJECT_AS_ARRAY);
        //签发时间大于当前服务器时间验证失败 接口还没有到调用时间
        if (isset($payload['start_time']) && $payload['start_time'] > time()){
            return false;
        }
        //接口已经过期
        if (isset($payload['expire_time']) && $payload['expire_time'] < time()){
            return false;
        }
        //该nbf时间之前不接收处理该Token
        if (isset($payload['nbf']) && $payload['nbf'] > time()){
            return false;
        }
        return $payload;
    }

    /**
     * HMACSHA256签名  https://jwt.io/ 中HMACSHA256签名实现
     * @param string $input 为base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key
     * @return mixed
     */
    private function signature($input,$key) {
        $alg_config = array(
            'HS256' => 'sha256'
        );
        return self::base64UrlEncode(hash_hmac($alg_config[$this->headers["alg"]], $input, $key, true));
    }

    /**
     * base64UrlEncode  https://jwt.io/ 中base64UrlEncode编码实现
     * @param string $input 需要编码的字符串
     * @return string
     */
    private function base64UrlEncode($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * base64UrlEncode https://jwt.io/ 中base64UrlEncode解码实现
     * @param string $input 需要解码的字符串
     * @return bool|string
     */
    private function base64UrlDecode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

}
