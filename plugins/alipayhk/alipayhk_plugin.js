/**
 * AlipayHK 支付插件
 * 移植自PHP版本
 */

const crypto = require('crypto');
const axios = require('axios');

// 插件信息
const info = {
    name: 'alipayhk',
    showname: 'AlipayHK',
    author: '支付宝',
    link: 'https://global.alipay.com/',
    types: ['alipay'],
    inputs: {
        appid: {
            name: 'Partner ID',
            type: 'input',
            note: ''
        },
        appkey: {
            name: 'MD5 Key',
            type: 'input',
            note: ''
        },
        appswitch: {
            name: '支付时选择钱包类型',
            type: 'select',
            options: {
                '0': '否',
                '1': '是'
            }
        }
    },
    select: {
        '1': 'PC支付',
        '2': 'WAP支付',
        '3': 'APP支付'
    },
    note: '支付时选择钱包类型开启后，支付时可选择Alipay或AlipayHK，关闭则默认使用Alipay',
    bindwxmp: false,
    bindwxa: false
};

const GATEWAY_URL = 'https://intlmapi.alipay.com/gateway.do';

// 交易信息
const TRADE_INFORMATION = {
    business_type: '5',
    other_business_type: '在线充值'
};

/**
 * MD5签名
 */
function md5Sign(params, key) {
    const sortedKeys = Object.keys(params).sort();
    const signParts = [];
    
    for (const k of sortedKeys) {
        const v = params[k];
        if (k !== 'sign' && k !== 'sign_type' && v !== undefined && v !== null && v !== '') {
            signParts.push(`${k}=${v}`);
        }
    }
    
    const signString = signParts.join('&') + key;
    return crypto.createHash('md5').update(signString, 'utf8').digest('hex');
}

/**
 * 验证MD5签名
 */
function verifySign(params, key) {
    const sign = params.sign;
    const calculatedSign = md5Sign(params, key);
    return sign === calculatedSign;
}

/**
 * 构建支付表单
 */
function buildPayForm(params) {
    let formHtml = `<form id="alipayForm" action="${GATEWAY_URL}" method="post">`;
    for (const [key, value] of Object.entries(params)) {
        formHtml += `<input type="hidden" name="${key}" value="${String(value).replace(/"/g, '&quot;')}">`;
    }
    formHtml += '</form><script>document.getElementById("alipayForm").submit();</script>';
    return formHtml;
}

/**
 * 发起支付
 */
async function submit(channelConfig, orderInfo, conf) {
    const { trade_no, is_wechat } = orderInfo;
    
    // 在微信浏览器中需要跳转
    if (is_wechat) {
        return { type: 'page', page: 'wxopen' };
    }
    
    return {
        type: 'jump',
        url: `/pay/alipay/${trade_no}/`
    };
}

/**
 * 支付处理 - 根据设备和配置选择支付方式
 */
async function alipay(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, return_url, is_mobile, is_alipay, apptype, payment_inst } = orderInfo;
    const siteurl = conf.siteurl || '';
    
    // 如果开启了钱包选择且没有指定类型，显示选择页面
    if (channelConfig.appswitch === '1' && !payment_inst) {
        return {
            type: 'page',
            page: 'alipayhk_select',
            data: {
                trade_no: trade_no,
                options: [
                    { type: 'ALIPAYCN', name: 'Alipay (支付宝)' },
                    { type: 'ALIPAYHK', name: 'AlipayHK' }
                ]
            }
        };
    }
    
    // 移动端
    if (is_mobile) {
        if (apptype && apptype.includes('2')) {
            return await wappay(channelConfig, orderInfo, conf);
        } else if (apptype && apptype.includes('1')) {
            return await submitpc(channelConfig, orderInfo, conf);
        } else if (apptype && apptype.includes('3')) {
            if (is_alipay) {
                return await apppay(channelConfig, orderInfo, conf);
            } else {
                const code_url = `${siteurl}pay/apppay/${trade_no}/${payment_inst ? '?type=' + payment_inst : ''}`;
                return { type: 'qrcode', page: 'alipay_qrcode', url: code_url };
            }
        }
    } else {
        // PC端
        if (apptype && apptype.includes('1')) {
            const code_url = `/pay/submitpc/${trade_no}/${payment_inst ? '?type=' + payment_inst : ''}`;
            return { type: 'qrcode', page: 'alipay_qrcodepc', url: code_url };
        } else if (apptype && apptype.includes('2')) {
            const code_url = `${siteurl}pay/wappay/${trade_no}/${payment_inst ? '?type=' + payment_inst : ''}`;
            return { type: 'qrcode', page: 'alipay_qrcode', url: code_url };
        } else if (apptype && apptype.includes('3')) {
            const code_url = `${siteurl}pay/apppay/${trade_no}/${payment_inst ? '?type=' + payment_inst : ''}`;
            return { type: 'qrcode', page: 'alipay_qrcode', url: code_url };
        }
    }
    
    // 默认WAP支付
    return await wappay(channelConfig, orderInfo, conf);
}

/**
 * PC支付
 */
async function submitpc(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, return_url, is_mobile, is_alipay, payment_inst } = orderInfo;
    const siteurl = conf.siteurl || '';
    
    const params = {
        service: 'create_forex_trade',
        partner: channelConfig.appid,
        notify_url: notify_url,
        return_url: return_url,
        out_trade_no: trade_no,
        subject: name,
        currency: 'HKD',
        rmb_fee: money.toFixed(2),
        refer_url: siteurl,
        product_code: 'NEW_WAP_OVERSEAS_SELLER',
        qr_pay_mode: '4',
        qrcode_width: '230',
        trade_information: JSON.stringify(TRADE_INFORMATION),
        _input_charset: 'utf-8'
    };
    
    if (payment_inst) {
        params.payment_inst = payment_inst;
    }
    
    params.sign = md5Sign(params, channelConfig.appkey);
    params.sign_type = 'MD5';
    
    // 移动端非支付宝内，需要获取二维码
    if (is_mobile && !is_alipay) {
        try {
            const response = await axios.get(GATEWAY_URL, { params: params });
            const html = response.data;
            const match = html.match(/<input name="qrCode" type="hidden" value="(.*?)"/i);
            if (match && match[1]) {
                return { type: 'qrcode', page: 'alipay_qrcode', url: match[1] };
            } else {
                return { type: 'error', msg: '支付宝下单失败！获取二维码失败' };
            }
        } catch (error) {
            return { type: 'error', msg: error.message };
        }
    }
    
    const formHtml = buildPayForm(params);
    return { type: 'html', data: formHtml };
}

/**
 * WAP支付
 */
async function wappay(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, return_url, payment_inst } = orderInfo;
    const siteurl = conf.siteurl || '';
    
    const params = {
        service: 'create_forex_trade_wap',
        partner: channelConfig.appid,
        notify_url: notify_url,
        return_url: return_url,
        out_trade_no: trade_no,
        subject: name,
        currency: 'HKD',
        rmb_fee: money.toFixed(2),
        refer_url: siteurl,
        product_code: 'NEW_WAP_OVERSEAS_SELLER',
        trade_information: JSON.stringify(TRADE_INFORMATION),
        _input_charset: 'utf-8'
    };
    
    if (payment_inst) {
        params.payment_inst = payment_inst;
    }
    
    params.sign = md5Sign(params, channelConfig.appkey);
    params.sign_type = 'MD5';
    
    const formHtml = buildPayForm(params);
    return { type: 'html', data: formHtml };
}

/**
 * APP支付
 */
async function apppay(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, return_url, method, payment_inst } = orderInfo;
    const siteurl = conf.siteurl || '';
    
    const params = {
        service: 'mobile.securitypay.pay',
        partner: channelConfig.appid,
        notify_url: notify_url,
        return_url: return_url,
        out_trade_no: trade_no,
        subject: name,
        payment_type: '1',
        seller_id: channelConfig.appid,
        currency: 'HKD',
        rmb_fee: money.toFixed(2),
        forex_biz: 'FP',
        refer_url: siteurl,
        product_code: 'NEW_WAP_OVERSEAS_SELLER',
        trade_information: JSON.stringify(TRADE_INFORMATION),
        _input_charset: 'utf-8'
    };
    
    if (payment_inst) {
        params.payment_inst = payment_inst;
    }
    
    params.sign = md5Sign(params, channelConfig.appkey);
    params.sign_type = 'MD5';
    
    // 构建SDK参数字符串
    const sdkParams = Object.entries(params)
        .map(([k, v]) => `${k}="${v}"`)
        .join('&');
    
    // 如果是APP直接调用
    if (method === 'app') {
        return { type: 'app', data: sdkParams };
    }
    
    // H5唤起支付宝APP
    const redirect_url = orderInfo.d === '1' ? 'data.backurl' : `'/pay/ok/${trade_no}/'`;
    const code_url = `alipays://platformapi/startApp?appId=20000125&orderSuffix=${encodeURIComponent(sdkParams)}#Intent;scheme=alipays;package=com.eg.android.AlipayGphone;end`;
    
    return {
        type: 'page',
        page: 'alipay_h5',
        data: {
            code_url: code_url,
            redirect_url: redirect_url
        }
    };
}

/**
 * 支付成功页面
 */
async function ok(channelConfig, orderInfo) {
    return { type: 'page', page: 'ok' };
}

/**
 * 异步通知
 */
async function notify(channelConfig, notifyData, order) {
    try {
        const isValid = verifySign(notifyData, channelConfig.appkey);
        
        if (!isValid) {
            console.log('AlipayHK回调验签失败');
            return { success: false };
        }
        
        const out_trade_no = notifyData.out_trade_no;
        const trade_no = notifyData.trade_no;
        const buyer_id = notifyData.buyer_id || '';
        
        if (notifyData.trade_status === 'TRADE_FINISHED' || notifyData.trade_status === 'TRADE_SUCCESS') {
            if (out_trade_no === order.trade_no) {
                return {
                    success: true,
                    api_trade_no: trade_no,
                    buyer: buyer_id
                };
            }
        }
        
        return { success: false };
    } catch (error) {
        console.error('AlipayHK回调处理错误:', error);
        return { success: false };
    }
}

/**
 * 同步回调
 */
async function returnCallback(channelConfig, params, order) {
    const isValid = verifySign(params, channelConfig.appkey);
    
    if (isValid) {
        if (params.trade_status === 'TRADE_FINISHED' || params.trade_status === 'TRADE_SUCCESS') {
            if (params.out_trade_no === order.trade_no) {
                return { type: 'page', page: 'return' };
            }
        }
    }
    
    return { type: 'error', msg: '支付验证失败' };
}

/**
 * 退款
 */
async function refund(channelConfig, refundInfo) {
    const { trade_no, refund_money, refund_no } = refundInfo;
    
    const params = {
        service: 'forex_refund',
        partner: channelConfig.appid,
        out_return_no: refund_no,
        out_trade_no: trade_no,
        return_rmb_amount: refund_money.toFixed(2),
        currency: 'HKD',
        gmt_return: new Date().toISOString().replace('T', ' ').substring(0, 19),
        _input_charset: 'utf-8'
    };
    
    params.sign = md5Sign(params, channelConfig.appkey);
    params.sign_type = 'MD5';
    
    try {
        const response = await axios.post(GATEWAY_URL, null, {
            params: params
        });
        
        // 解析XML响应
        const result = response.data;
        if (result.includes('is_success') && result.includes('T')) {
            return { code: 0 };
        } else {
            return { code: 1, msg: '退款失败' };
        }
    } catch (error) {
        return { code: 1, msg: error.message };
    }
}

module.exports = {
    info,
    submit,
    alipay,
    submitpc,
    wappay,
    apppay,
    notify,
    return: returnCallback,
    refund
};
