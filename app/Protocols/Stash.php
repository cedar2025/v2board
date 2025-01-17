<?php

namespace App\Protocols;

use App\Models\ServerHysteria;
use Symfony\Component\Yaml\Yaml;

class Stash
{
    public $flag = 'stash';
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
        $appName = admin_setting('app_name', 'XBoard');
        // 暂时使用clash配置文件，后续根据Stash更新情况更新
        $defaultConfig = base_path() . '/resources/rules/default.clash.yaml';
        $customClashConfig = base_path() . '/resources/rules/custom.clash.yaml';
        $customStashConfig = base_path() . '/resources/rules/custom.stash.yaml';
        if (\File::exists($customStashConfig)) {
            $config = Yaml::parseFile($customStashConfig);
        } elseif (\File::exists($customClashConfig)) {
            $config = Yaml::parseFile($customClashConfig);
        } else {
            $config = Yaml::parseFile($defaultConfig);
        }
        $proxy = [];
        $proxies = [];

        foreach ($servers as $item) {
            if ($item['type'] === 'shadowsocks'
                && in_array($item['cipher'], [
                    'aes-128-gcm',
                    'aes-192-gcm',
                    'aes-256-gcm',
                    'chacha20-ietf-poly1305'
                ])
            ) {
                array_push($proxy, self::buildShadowsocks($item['password'], $item));
                array_push($proxies, $item['name']);
            }
            if ($item['type'] === 'vmess') {
                array_push($proxy, self::buildVmess($user['uuid'], $item));
                array_push($proxies, $item['name']);
            }
            // if ($item['type'] === 'vless') {
            //     array_push($proxy, self::buildVless($user['uuid'], $item));
            //     array_push($proxies, $item['name']);
            // }
            if ($item['type'] === 'hysteria') {
                array_push($proxy, self::buildHysteria($user['uuid'], $item));
                array_push($proxies, $item['name']);
            }
            if ($item['type'] === 'trojan') {
                array_push($proxy, self::buildTrojan($user['uuid'], $item));
                array_push($proxies, $item['name']);
            }
        }

        $config['proxies'] = array_merge($config['proxies'] ? $config['proxies'] : [], $proxy);
        foreach ($config['proxy-groups'] as $k => $v) {
            if (!is_array($config['proxy-groups'][$k]['proxies'])) $config['proxy-groups'][$k]['proxies'] = [];
            $isFilter = false;
            foreach ($config['proxy-groups'][$k]['proxies'] as $src) {
                foreach ($proxies as $dst) {
                    if (!$this->isRegex($src)) continue;
                    $isFilter = true;
                    $config['proxy-groups'][$k]['proxies'] = array_values(array_diff($config['proxy-groups'][$k]['proxies'], [$src]));
                    if ($this->isMatch($src, $dst)) {
                        array_push($config['proxy-groups'][$k]['proxies'], $dst);
                    }
                }
                if ($isFilter) continue;
            }
            if ($isFilter) continue;
            $config['proxy-groups'][$k]['proxies'] = array_merge($config['proxy-groups'][$k]['proxies'], $proxies);
        }
        $config['proxy-groups'] = array_filter($config['proxy-groups'], function($group) {
            return $group['proxies'];
        });
        $config['proxy-groups'] = array_values($config['proxy-groups']);
        // Force the current subscription domain to be a direct rule
        $subsDomain = request()->header('Host');
        if ($subsDomain) {
            array_unshift($config['rules'], "DOMAIN,{$subsDomain},DIRECT");
        }

        $yaml = Yaml::dump($config, 2, 4, Yaml::DUMP_EMPTY_ARRAY_AS_SEQUENCE);
        $yaml = str_replace('$app_name', admin_setting('app_name', 'XBoard'), $yaml);
        return response($yaml, 200)
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}")
            ->header('profile-update-interval', '24')
            ->header('content-disposition', 'attachment;filename*=UTF-8\'\'' . rawurlencode($appName));
    }

    public static function buildShadowsocks($uuid, $server)
    {
        $array = [];
        $array['name'] = $server['name'];
        $array['type'] = 'ss';
        $array['server'] = $server['host'];
        $array['port'] = $server['port'];
        $array['cipher'] = $server['cipher'];
        $array['password'] = $uuid;
        $array['udp'] = true;
        return $array;
    }

    public static function buildVmess($uuid, $server)
    {
        $array = [];
        $array['name'] = $server['name'];
        $array['type'] = 'vmess';
        $array['server'] = $server['host'];
        $array['port'] = $server['port'];
        $array['uuid'] = $uuid;
        $array['alterId'] = 0;
        $array['cipher'] = 'auto';
        $array['udp'] = true;

        if ($server['tls']) {
            $array['tls'] = true;
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['allowInsecure']) && !empty($tlsSettings['allowInsecure']))
                    $array['skip-cert-verify'] = ($tlsSettings['allowInsecure'] ? true : false);
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $array['servername'] = $tlsSettings['serverName'];
            }
        }
        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['networkSettings'];
            if (isset($tcpSettings['header']['type'])) $array['network'] = $tcpSettings['header']['type'];
            if (isset($tcpSettings['header']['request']['path'][0])) $array['http-opts']['path'] = $tcpSettings['header']['request']['path'][0];
        }
        if ($server['network'] === 'ws') {
            $array['network'] = 'ws';
            if ($server['networkSettings']) {
                $wsSettings = $server['networkSettings'];
                $array['ws-opts'] = [];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $array['ws-opts']['path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $array['ws-opts']['headers'] = ['Host' => $wsSettings['headers']['Host']];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $array['ws-path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $array['ws-headers'] = ['Host' => $wsSettings['headers']['Host']];
            }
        }
        if ($server['network'] === 'grpc') {
            $array['network'] = 'grpc';
            if ($server['networkSettings']) {
                $grpcSettings = $server['networkSettings'];
                $array['grpc-opts'] = [];
                if (isset($grpcSettings['serviceName']))  $array['grpc-opts']['grpc-service-name'] = $grpcSettings['serviceName'];
            }
        }

        return $array;
    }

    public static function buildVless($uuid, $server)
    {
        $array = [];
        $array['name'] = $server['name'];
        $array['type'] = 'vless';
        $array['server'] = $server['host'];
        $array['port'] = $server['port'];
        $array['uuid'] = $uuid;
        $array['flow'] = !empty($server['flow']) ? $server['flow']: "";
        $array['udp'] = true;

        $fingerprints = ['chrome', 'firefox', 'safari', 'ios', 'edge', 'qq']; //随机客户端指纹
        $array['client-fingerprint'] = $fingerprints[rand(0,count($fingerprints) - 1)];

        if ($server['tls']) {
            $array['tls'] = true;
            switch($server['tls']){
                case 1:
                    if ($server['tls_settings']) {
                        $tlsSettings = $server['tls_settings'];
                        if (isset($tlsSettings['allow_insecure']) && !empty($tlsSettings['allow_insecure']))
                            $array['skip-cert-verify'] = ($tlsSettings['allow_insecure'] ? true : false);
                        if (isset($tlsSettings['server_name']) && !empty($tlsSettings['server_name']))
                            $array['servername'] = $tlsSettings['server_name'];
                    }
                    break;
                case 2:
                    if (!isset($server['network_settings'])) break;
                    $networkSettings = $server['network_settings'];
                    if (isset($networkSettings['reality-opts'])){
                        $realitySettings = $networkSettings['reality-opts'];
                        $array['reality-opts'] = [];
                        $array['reality-opts']['public-key'] = $realitySettings['public-key'];
                        $array['reality-opts']['short-id'] = $realitySettings['short-id'];
                    }
                    break;
            }

        }

        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['networkSettings'];
            if (isset($tcpSettings['header']['type']) && $tcpSettings['header']['type'] == 'http') {
                $array['network'] = $tcpSettings['header']['type'];
                if (isset($tcpSettings['header']['request']['headers']['Host'])){
                    $array['http-opts']['headers']['Host'] = $tcpSettings['header']['request']['headers']['Host'];
                }
                if (isset($tcpSettings['header']['request']['path'][0])){
                    $paths = $tcpSettings['header']['request']['path'];
                    $array['http-opts']['path'] = $paths[array_rand($paths)];
                };
            }
        }

        if ($server['network'] === 'ws') {
            $array['network'] = 'ws';
            if ($server['network_settings']) {
                $wsSettings = $server['network_settings'];
                $array['ws-opts'] = [];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $array['ws-opts']['path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $array['ws-opts']['headers'] = ['Host' => $wsSettings['headers']['Host']];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $array['ws-path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $array['ws-headers'] = ['Host' => $wsSettings['headers']['Host']];
            }
        }
        if ($server['network'] === 'grpc') {
            $array['network'] = 'grpc';
            if ($server['network_settings']) {
                $grpcSettings = $server['network_settings'];
                $array['grpc-opts'] = [];
                if (isset($grpcSettings['serviceName'])) $array['grpc-opts']['grpc-service-name'] = $grpcSettings['serviceName'];
            }
        }

        return $array;
    }

    public static function buildTrojan($password, $server)
    {
        $array = [];
        $array['name'] = $server['name'];
        $array['type'] = 'trojan';
        $array['server'] = $server['host'];
        $array['port'] = $server['port'];
        $array['password'] = $password;
        $array['udp'] = true;
        // trojan-go配置
        if(in_array($server['network'], ["grpc", "ws"])){
            $array['network'] = $server['network'];
            // grpc配置
            if($server['network'] === "grpc" && isset($server['networkSettings']['serviceName'])) $array['grpc-opts']['grpc-service-name'] = $server['networkSettings']['serviceName'];
            // ws配置
            if($server['network'] === "ws") {
                if(isset($server['networkSettings']['path'])) {
                    $array['ws-opts']['path'] = $server['networkSettings']['path'];
                }
                if(isset($server['networkSettings']['headers']['Host'])){
                    $array['ws-opts']['headers']['Host'] = $server['networkSettings']['headers']['Host'];
                }
            }
        };
        if (!empty($server['server_name'])) $array['sni'] = $server['server_name'];
        if (!empty($server['allow_insecure'])) $array['skip-cert-verify'] = ($server['allow_insecure'] ? true : false);
        return $array;
    }

    public static function buildHysteria($password, $server)
    {
        $array = [];
        $array['name'] = $server['name'];
        $array['server'] = $server['host'];
        $array['port'] = $server['port'];
        $array['up-speed'] = $server['up_mbps'];
        $array['down-speed'] = $server['down_mbps'];
        $array['skip-cert-verify'] = $server['insecure'];
        $array['sni'] = $server['server_name']??'';
        switch($server['version']){
            case 1:
                $array['type'] = 'hysteria';
                $array['auth-str'] = $password;
                $array['protocol'] = 'udp';
                $array['obfs'] = $server['server_key'];
                $array['alpn'] = [ServerHysteria::$alpnMap[$server['alpn']]];
                break;
            case 2:
                $array['type'] = 'hysteria2';
                $array['auth'] = $password;
                $array['fast-open'] = true;
                if(isset($server['ports'])) $array['ports'] = $server['ports'];
                break;
        }
        return $array;

    }

    private function isRegex($exp)
    {
        return @preg_match($exp, null) !== false;
    }

    private function isMatch($exp, $str)
    {
        try {
            return preg_match($exp, $str);
        } catch (\Exception $e) {
            return false;
        }
    }
}
