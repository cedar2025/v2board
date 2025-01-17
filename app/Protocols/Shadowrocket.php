<?php

namespace App\Protocols;

use App\Models\ServerHysteria;
use App\Utils\Helper;

class Shadowrocket
{
    public $flag = 'shadowrocket';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;

        $uri = '';
        //display remaining traffic and expire date
        $upload = round($user['u'] / (1024*1024*1024), 2);
        $download = round($user['d'] / (1024*1024*1024), 2);
        $totalTraffic = round($user['transfer_enable'] / (1024*1024*1024), 2);
        $expiredDate = date('Y-m-d', $user['expired_at']);
        $uri .= "STATUS=🚀↑:{$upload}GB,↓:{$download}GB,TOT:{$totalTraffic}GB💡Expires:{$expiredDate}\r\n";
        foreach ($servers as $item) {
            if ($item['type'] === 'shadowsocks') {
                $uri .= self::buildShadowsocks($item['password'], $item);
            }
            if ($item['type'] === 'vmess') {
                $uri .= self::buildVmess($user['uuid'], $item);
            }
            if ($item['type'] === 'vless') {
                $uri .= self::buildVless($user['uuid'], $item);
            }
            if ($item['type'] === 'trojan') {
                $uri .= self::buildTrojan($user['uuid'], $item);
            }
            if ($item['type'] === 'hysteria') {
                $uri .= self::buildHysteria($user['uuid'], $item);
            }
        }
        return base64_encode($uri);
    }


    public static function buildShadowsocks($password, $server)
    {
        $name = rawurlencode($server['name']);
        $str = str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode("{$server['cipher']}:{$password}")
        );
        $uri = "ss://{$str}@{$server['host']}:{$server['port']}";
        if ($server['obfs'] == 'http') {
            $uri .= "?plugin=obfs-local;obfs=http;obfs-host={$server['obfs-host']};obfs-uri={$server['obfs-path']}";
        }
        return $uri."#{$name}\r\n";
    }

    public static function buildVmess($uuid, $server)
    {
        $userinfo = base64_encode('auto:' . $uuid . '@' . $server['host'] . ':' . $server['port']);
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
            'alterId' => 0
        ];
        if ($server['tls']) {
            $config['tls'] = 1;
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['allowInsecure']) && !empty($tlsSettings['allowInsecure']))
                    $config['allowInsecure'] = (int)$tlsSettings['allowInsecure'];
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $config['peer'] = $tlsSettings['serverName'];
            }
        }
        if ($server['network'] === 'tcp') {
            if ($server['networkSettings']) {
                $tcpSettings = $server['networkSettings'];
                if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']))
                    $config['obfs'] = $tcpSettings['header']['type'];
                if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                    $config['path'] = $tcpSettings['header']['request']['path'][0];
            }
        }
        if ($server['network'] === 'ws') {
            $config['obfs'] = "websocket";
            if ($server['networkSettings']) {
                $wsSettings = $server['networkSettings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $config['path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $config['obfsParam'] = $wsSettings['headers']['Host'];
            }
        }
        if ($server['network'] === 'grpc') {
            $config['obfs'] = "grpc";
            if ($server['networkSettings']) {
                $grpcSettings = $server['networkSettings'];
                if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName']))
                    $config['path'] = $grpcSettings['serviceName'];
            }
            if (isset($tlsSettings)) {
                $config['host'] = $tlsSettings['serverName'];
            } else {
                $config['host'] = $server['host'];
            }
        }
        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vmess://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildVless($uuid, $server)
    {
        $userinfo = base64_encode('auto:' . $uuid . '@' . $server['host'] . ':' . $server['port']);
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
            'alterId' => 0
        ];

        // 判断是否开启xtls
        if(isset($server['flow']) && !blank($server['flow'])){
            $xtlsMap = [
                'none' => 0,
                'xtls-rprx-direct' => 1,
                'xtls-rprx-vision' => 2
            ];
            // 判断 flow 的值是否在 xtlsMap 中存在
            if (array_key_exists($server['flow'], $xtlsMap)) {
                $config['tls'] = 1;
                $config['xtls'] = $xtlsMap[$server['flow']];
            }
        }

        if ($server['tls']) {
            switch($server['tls']){
                case 1:
                    $config['tls'] = 1;
                    if ($server['tls_settings']) {
                        $tlsSettings = $server['tls_settings'];
                        if (isset($tlsSettings['allow_insecure']) && !empty($tlsSettings['allow_insecure']))
                            $config['allowInsecure'] = (int)$tlsSettings['allow_insecure'];
                        if (isset($tlsSettings['server_name']) && !empty($tlsSettings['server_name']))
                            $config['peer'] = $tlsSettings['server_name'];
                    }
                    break;
                case 2:
                    $config['tls'] = 1;
                    $tls_settings = $server['tls_settings'];
                    if(($tls_settings['public_key'] ?? null)
                    && ($tls_settings['short_id'] ?? null)
                    && ($tls_settings['server_name'] ?? null)){
                        $config['sni'] = $tls_settings['server_name'];
                        $config['pbk'] = $tls_settings['public_key'];
                        $config['sid'] = $tls_settings['short_id'];
                        $fingerprints = ['chrome', 'firefox', 'safari', 'ios', 'edge', 'qq']; //随机客户端指纹
                        $config['fp'] = $fingerprints[rand(0,count($fingerprints) - 1)];
                    };
                    break;
            }

        }
        if ($server['network'] === 'tcp') {
            if ($server['network_settings']) {
                $tcpSettings = $server['network_settings'];
                if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']))
                    $config['obfs'] = $tcpSettings['header']['type'];
                if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                    $config['path'] = $tcpSettings['header']['request']['path'][0];
                if (isset($tcpSettings['header']['request']['headers']['Host'][0])){
                    $hosts = $tcpSettings['header']['request']['headers']['Host'];
                    $config['obfsParam'] = $hosts[array_rand($hosts)];
                }
            }
        }
        if ($server['network'] === 'ws') {
            $config['obfs'] = "websocket";
            if ($server['network_settings']) {
                $wsSettings = $server['network_settings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $config['path'] = $wsSettings['path'] . '?ed=2560';
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $config['obfsParam'] = $wsSettings['headers']['Host'];
            }
        }
        if ($server['network'] === 'grpc') {
            $config['obfs'] = "grpc";
            if ($server['network_settings']) {
                $grpcSettings = $server['network_settings'];
                if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName']))
                    $config['path'] = $grpcSettings['serviceName'];
            }
            if (isset($tlsSettings)) {
                $config['host'] = $tlsSettings['server_name'];
            } else {
                $config['host'] = $server['host'];
            }
        }

        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vless" . "://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildTrojan($password, $server)
    {
        $name = rawurlencode($server['name']);
        $params = [
            'allowInsecure' => $server['allow_insecure'],
            'peer' => $server['server_name']
        ];
        // trojan-go配置
        if(in_array($server['network'], ["grpc", "ws"])){
            // grpc配置
            if($server['network'] === "grpc" && isset($server['networkSettings']['serviceName'])) {
                $params['obfs'] = 'grpc';
                $params['path'] = $server['networkSettings']['serviceName'];
            }
            // ws配置
            if($server['network'] === "ws") {
                $path = '';
                $host = '';
                if(isset($server['networkSettings']['path'])) {
                    $path = $server['networkSettings']['path'];
                }
                if(isset($server['networkSettings']['headers']['Host'])){
                    $host = $server['networkSettings']['headers']['Host'];
                }
                $params['plugin'] = "obfs-local;obfs=websocket;obfs-host={$host};obfs-uri={$path}";
            }
        };
        $query = http_build_query($params);
        $uri = "trojan://{$password}@{$server['host']}:{$server['port']}?{$query}&tfo=1#{$name}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildHysteria($password, $server)
    {
        switch($server['version']){
            case 1:
                $params = [
                    "auth" => $password,
                    "upmbps" => $server['up_mbps'],
                    "downmbps" => $server['down_mbps'],
                    "protocol" => 'udp',
                    "peer" => $server['server_name'],
                    "fastopen" => 1,
                    "alpn" => ServerHysteria::$alpnMap[$server['alpn']]
                ];
                if($server['is_obfs']){
                    $params["obfs"] = "xplus";
                    $params["obfsParam"] =$server['server_key'];
                }
                if($server['insecure']) $params['insecure'] = $server['insecure'];
                if(isset($server['ports'])) $params['mport'] = $server['ports'];
                $query = http_build_query($params);
                $uri = "hysteria://{$server['host']}:{$server['port']}?{$query}#{$server['name']}";
                $uri .= "\r\n";
                break;
            case 2:
                $params = [
                    "peer" => $server['server_name'],
                    "obfs" => 'none',
                    "fastopen" => 1
                ];
                if($server['is_obfs']) $params['obfs-password'] = $server['server_key'];
                if($server['insecure']) $params['insecure'] = $server['insecure'];
                if(isset($server['ports'])) $params['mport'] = $server['ports'];
                $query = http_build_query($params);
                $uri = "hysteria2://{$password}@{$server['host']}:{$server['port']}?{$query}#{$server['name']}";
                $uri .= "\r\n";
                break;
        }
        return $uri;
    }
}
