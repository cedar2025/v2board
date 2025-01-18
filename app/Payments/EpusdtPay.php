<?php
//author by GoodGoodStudy 
namespace App\Payments;

use \Curl\Curl;

class EpusdtPay {
    public function __construct($config)
    {
        $this->config = $config;
    }

    public function form()
    {
        return [
            'epusdt_pay_url' => [
                'label' => 'API 地址',
                'description' => '您的 EpusdtPay API 接口地址(例如: https://epusdt-pay.xxx.com)',
                'type' => 'input',
            ],
            'epusdt_pay_apitoken' => [
                'label' => 'API Token',
                'description' => '您的 EpusdtPay API Token',
                'type' => 'input',
            ]
        ];
    }

    public function pay($order)
    {
        $params = [
			"amount" => round($order['total_amount']/100,2),
			"order_id" => $order['trade_no'],
			'redirect_url' => $order['return_url'],
			'notify_url' => $order['notify_url'],
        ];
        $params['signature'] = $this->sign($params);

        $curl = new Curl();
        $curl->setUserAgent('EpusdtPay');
        $curl->setOpt(CURLOPT_SSL_VERIFYPEER, 0);
        $curl->setOpt(CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
        $curl->post($this->config['epusdt_pay_url'] . '/api/v1/order/create-transaction', json_encode($params));
        $result = $curl->response;
        $curl->close();
        if (!isset($result->status_code) || $result->status_code != 200) {
            abort(500, "Failed to create order. Error: {$result->message}");
        }
        return [
            'type' => 1, // 0:qrcode 1:url
            'data' => $result->data->payment_url
        ];
    }

    public function notify($params)
    {
        $status = $params['status'];
        // 1：等待支付，2：支付成功，3：已过期
        if ($status != 2) {
            die('failed');
        }
        //不合法的数据
        if (!$this->verify($params)) {
            die('cannot pass verification');
        }
        return [
            'trade_no' => $params['order_id'],
            'callback_no' => $params['trade_id'],
            'custom_result' => 'ok'
        ];
    }

    public function verify($params) {
        return $params['signature'] === $this->sign($params);
    }

    protected function sign(array $params)
    {
        ksort($params);
        reset($params); //内部指针指向数组中的第一个元素
        $sign = '';
        $urls = '';
        foreach ($params as $key => $val) {
            if ($val == '') continue;
            if ($key != 'signature') {
                if ($sign != '') {
                    $sign .= "&";
                    $urls .= "&";
                }
                $sign .= "$key=$val"; //拼接为url参数形式
                $urls .= "$key=" . urlencode($val); //拼接为url参数形式
            }
        }
        $sign = md5($sign . $this->config['epusdt_pay_apitoken']);//密码追加进入开始MD5签名
        return $sign;
    }
}
