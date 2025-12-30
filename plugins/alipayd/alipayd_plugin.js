/**
 * 支付宝官方支付直付通版插件
 * 移植自PHP版本
 */

const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const certValidator = require('../../utils/certValidator');

// 插件信息
const info = {
    name: 'alipayd',
    showname: '支付宝官方支付直付通版',
    author: '支付宝',
    link: 'https://b.alipay.com/signing/productSetV2.htm',
    types: ['alipay'],
    inputs: {
        appid: {
            name: '应用APPID',
            type: 'input',
            note: ''
        },
        appkey: {
            name: '支付宝公钥',
            type: 'textarea',
            note: '填错也可以支付成功但会无法回调，如果用公钥证书模式此处留空'
        },
        appsecret: {
            name: '应用私钥',
            type: 'textarea',
            note: ''
        },
        appmchid: {
            name: '子商户SMID',
            type: 'input',
            note: ''
        }
    },
    select: {
        '1': '电脑网站支付',
        '2': '手机网站支付',
        '3': '当面付扫码',
        '4': '当面付JS',
        '5': '预授权支付',
        '6': 'APP支付',
        '7': 'JSAPI支付',
        '8': '订单码支付'
    },
    certs: [
        { key: 'appCert', name: '应用公钥证书', ext: '.crt', desc: 'appCertPublicKey_应用APPID.crt', optional: true },
        { key: 'alipayCert', name: '支付宝公钥证书', ext: '.crt', desc: 'alipayCertPublicKey_RSA2.crt', optional: true },
        { key: 'alipayRootCert', name: '支付宝根证书', ext: '.crt', desc: 'alipayRootCert.crt', optional: true }
    ],
    note: '<p>需要先申请互联网平台直付通才能使用！</p><p>【可选】如果使用公钥证书模式，请上传3个证书文件，并将下方"支付宝公钥"留空</p>',
    bindwxmp: false,
    bindwxa: false
};

// 支付宝网关
const GATEWAY_URL = 'https://openapi.alipay.com/gateway.do';

/**
 * 获取证书绝对路径
 */
function getCertAbsolutePath(channel, certKey) {
  let config = channel.config;
  if (typeof config === 'string') {
    try { config = JSON.parse(config); } catch (e) { return null; }
  }
  const certFilename = config?.certs?.[certKey]?.filename;
  if (!certFilename) return null;
  return certValidator.getAbsolutePath(certFilename);
}

/**
 * 从证书中提取序列号 (appCertSN)
 */
function getCertSN(certPath) {
  try {
    const certContent = fs.readFileSync(certPath, 'utf8');
    const cert = new crypto.X509Certificate(certContent);
    const issuer = cert.issuer;
    const serialNumber = cert.serialNumber;
    const serialNumberDec = BigInt('0x' + serialNumber).toString();
    const signStr = issuer + serialNumberDec;
    return crypto.createHash('md5').update(signStr).digest('hex');
  } catch (e) {
    console.error('获取证书SN失败:', e.message);
    return null;
  }
}

/**
 * 提取根证书序列号 (alipayRootCertSN)
 */
function getRootCertSN(certPath) {
  try {
    const certContent = fs.readFileSync(certPath, 'utf8');
    const certs = certContent.split('-----END CERTIFICATE-----');
    const snList = [];
    for (let i = 0; i < certs.length - 1; i++) {
      const certPem = certs[i] + '-----END CERTIFICATE-----';
      try {
        const cert = new crypto.X509Certificate(certPem);
        const sigAlg = cert.signatureAlgorithm;
        if (sigAlg && (sigAlg.includes('sha1WithRSAEncryption') || sigAlg.includes('sha256WithRSAEncryption') || sigAlg.includes('SHA1') || sigAlg.includes('SHA256'))) {
          const issuer = cert.issuer;
          const serialNumber = cert.serialNumber;
          const serialNumberDec = BigInt('0x' + serialNumber).toString();
          const signStr = issuer + serialNumberDec;
          const sn = crypto.createHash('md5').update(signStr).digest('hex');
          snList.push(sn);
        }
      } catch (e) { }
    }
    return snList.join('_');
  } catch (e) {
    console.error('获取根证书SN失败:', e.message);
    return null;
  }
}

/**
 * 从证书文件中提取公钥
 */
function getPublicKeyFromCert(certPath) {
  try {
    const certContent = fs.readFileSync(certPath, 'utf8');
    const cert = new crypto.X509Certificate(certContent);
    return cert.publicKey.export({ type: 'spki', format: 'pem' });
  } catch (e) {
    console.error('从证书提取公钥失败:', e.message);
    return null;
  }
}

/**
 * RSA2签名
 */
function rsaSign(content, privateKey, signType = 'RSA2') {
    const sign = crypto.createSign(signType === 'RSA2' ? 'RSA-SHA256' : 'RSA-SHA1');
    sign.update(content, 'utf8');
    
    let formattedKey = privateKey;
    if (!privateKey.includes('-----BEGIN')) {
        formattedKey = `-----BEGIN RSA PRIVATE KEY-----\n${privateKey}\n-----END RSA PRIVATE KEY-----`;
    }
    
    return sign.sign(formattedKey, 'base64');
}

/**
 * RSA2验签
 */
function rsaVerify(content, sign, publicKey, signType = 'RSA2') {
    try {
        const verify = crypto.createVerify(signType === 'RSA2' ? 'RSA-SHA256' : 'RSA-SHA1');
        verify.update(content, 'utf8');
        
        let formattedKey = publicKey;
        if (!publicKey.includes('-----BEGIN')) {
            formattedKey = `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`;
        }
        
        return verify.verify(formattedKey, sign, 'base64');
    } catch (error) {
        console.error('验签错误:', error);
        return false;
    }
}

/**
 * 构建签名字符串
 */
function buildSignString(params) {
    const sortedKeys = Object.keys(params).sort();
    const signParts = [];
    
    for (const key of sortedKeys) {
        const value = params[key];
        if (key !== 'sign' && value !== undefined && value !== null && value !== '') {
            signParts.push(`${key}=${value}`);
        }
    }
    
    return signParts.join('&');
}

/**
 * 构建请求参数
 */
function buildRequestParams(config, method, bizContent, channelConfig = null) {
    const params = {
        app_id: config.appid,
        method: method,
        format: 'JSON',
        charset: 'utf-8',
        sign_type: 'RSA2',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        version: '1.0',
        biz_content: JSON.stringify(bizContent)
    };
    
    if (config.notify_url) {
        params.notify_url = config.notify_url;
    }
    
    if (config.return_url) {
        params.return_url = config.return_url;
    }
    
    // 检查是否为证书模式
    if (channelConfig) {
        const appCertPath = getCertAbsolutePath(channelConfig, 'appCert');
        const rootCertPath = getCertAbsolutePath(channelConfig, 'alipayRootCert');
        
        if (appCertPath && rootCertPath && fs.existsSync(appCertPath) && fs.existsSync(rootCertPath)) {
            const appCertSN = getCertSN(appCertPath);
            const alipayRootCertSN = getRootCertSN(rootCertPath);
            if (appCertSN) params.app_cert_sn = appCertSN;
            if (alipayRootCertSN) params.alipay_root_cert_sn = alipayRootCertSN;
        }
    }
    
    // 签名
    const signString = buildSignString(params);
    params.sign = rsaSign(signString, config.appsecret);
    
    return params;
}

/**
 * 发送请求到支付宝
 */
async function sendRequest(params) {
    const response = await axios.post(GATEWAY_URL, null, {
        params: params,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    return response.data;
}

/**
 * 发起支付
 */
async function submit(channelConfig, orderInfo) {
    const { trade_no, money, name, notify_url, return_url, clientip } = orderInfo;
    const apptype = channelConfig.apptype || [];
    
    const isMobile = orderInfo.is_mobile || false;
    const isAlipay = orderInfo.is_alipay || false;
    
    // 根据支付类型选择支付方式
    if (isAlipay && apptype.includes('4') && !apptype.includes('2')) {
        return { type: 'jump', url: `/pay/jspay/${trade_no}/?d=1` };
    } else if (isMobile && (apptype.includes('3') || apptype.includes('4') || apptype.includes('8')) && !apptype.includes('2') || !isMobile && !apptype.includes('1')) {
        return { type: 'jump', url: `/pay/qrcode/${trade_no}/` };
    }
    
    const config = {
        ...channelConfig,
        notify_url,
        return_url
    };
    
    const bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name
    };
    
    if (channelConfig.appmchid) {
        bizContent.extend_params = {
            sys_service_provider_id: channelConfig.appmchid
        };
    }
    
    // 添加客户端IP
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    if (isMobile && apptype.includes('2')) {
        // 手机网站支付
        const params = buildRequestParams(config, 'alipay.trade.wap.pay', bizContent, channelConfig);
        let formHtml = `<form id="alipayForm" action="${GATEWAY_URL}" method="post">`;
        for (const [key, value] of Object.entries(params)) {
            formHtml += `<input type="hidden" name="${key}" value="${String(value).replace(/"/g, '&quot;')}">`;
        }
        formHtml += '</form><script>document.getElementById("alipayForm").submit();</script>';
        return { type: 'html', data: formHtml };
    } else if (apptype.includes('1')) {
        // 电脑网站支付
        const params = buildRequestParams(config, 'alipay.trade.page.pay', bizContent, channelConfig);
        let formHtml = `<form id="alipayForm" action="${GATEWAY_URL}" method="post">`;
        for (const [key, value] of Object.entries(params)) {
            formHtml += `<input type="hidden" name="${key}" value="${String(value).replace(/"/g, '&quot;')}">`;
        }
        formHtml += '</form><script>document.getElementById("alipayForm").submit();</script>';
        return { type: 'html', data: formHtml };
    } else if (apptype.includes('6')) {
        // APP支付
        return { type: 'jump', url: `/pay/apppay/${trade_no}/?d=1` };
    } else if (apptype.includes('7')) {
        // JSAPI支付
        return { type: 'jump', url: `/pay/minipay/${trade_no}/?d=1` };
    } else if (apptype.includes('5')) {
        // 预授权支付
        return { type: 'jump', url: `/pay/preauth/${trade_no}/?d=1` };
    }
    
    return { type: 'jump', url: `/pay/qrcode/${trade_no}/` };
}

/**
 * 扫码支付
 */
async function qrcode(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, clientip } = orderInfo;
    const apptype = channelConfig.apptype || [];
    
    if (!apptype.includes('3') && apptype.includes('2')) {
        const siteurl = conf.siteurl || '';
        return { type: 'qrcode', page: 'alipay_qrcode', url: `${siteurl}pay/submitwap/${trade_no}/` };
    }
    
    const config = {
        ...channelConfig,
        notify_url
    };
    
    const bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name
    };
    
    if (channelConfig.appmchid) {
        bizContent.extend_params = {
            sys_service_provider_id: channelConfig.appmchid
        };
    }
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    const params = buildRequestParams(config, 'alipay.trade.precreate', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_precreate_response;
    if (result.code !== '10000') {
        throw new Error(result.sub_msg || result.msg || '获取支付二维码失败');
    }
    
    return {
        type: 'qrcode',
        page: 'alipay_qrcode',
        url: result.qr_code
    };
}

/**
 * 验证异步通知
 */
async function notify(channelConfig, notifyData, order) {
    try {
        const sign = notifyData.sign;
        const signType = notifyData.sign_type || 'RSA2';
        
        const params = { ...notifyData };
        delete params.sign;
        delete params.sign_type;
        
        const signString = buildSignString(params);
        
        // 检查是否使用证书模式
        let publicKey = channelConfig.appkey;
        const alipayCertPath = getCertAbsolutePath(channelConfig, 'alipayCert');
        if (alipayCertPath && fs.existsSync(alipayCertPath)) {
            const certPublicKey = getPublicKeyFromCert(alipayCertPath);
            if (certPublicKey) publicKey = certPublicKey;
        }
        
        if (!publicKey) {
            console.log('支付宝公钥未配置');
            return { success: false };
        }
        
        const isValid = rsaVerify(signString, sign, publicKey, signType);
        
        if (!isValid) {
            console.log('支付宝回调验签失败');
            return { success: false };
        }
        
        if (notifyData.out_trade_no !== order.trade_no) {
            return { success: false };
        }
        
        if (parseFloat(notifyData.total_amount) !== parseFloat(order.real_money)) {
            return { success: false };
        }
        
        if (notifyData.trade_status === 'TRADE_SUCCESS' || notifyData.trade_status === 'TRADE_FINISHED') {
            return {
                success: true,
                api_trade_no: notifyData.trade_no,
                buyer: notifyData.buyer_id || notifyData.buyer_open_id
            };
        }
        
        return { success: false };
    } catch (error) {
        console.error('支付宝回调处理错误:', error);
        return { success: false };
    }
}

/**
 * 退款
 */
async function refund(channelConfig, refundInfo) {
    const { trade_no, api_trade_no, refund_money, refund_no } = refundInfo;
    
    const bizContent = {
        out_request_no: refund_no,
        refund_amount: refund_money.toFixed(2)
    };
    
    if (api_trade_no) {
        bizContent.trade_no = api_trade_no;
    } else {
        bizContent.out_trade_no = trade_no;
    }
    
    const params = buildRequestParams(channelConfig, 'alipay.trade.refund', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_refund_response;
    if (result.code !== '10000') {
        throw new Error(result.sub_msg || result.msg || '退款失败');
    }
    
    return {
        code: 0,
        trade_no: result.trade_no,
        refund_fee: result.refund_fee,
        buyer: result.buyer_user_id
    };
}

/**
 * 关闭订单
 */
async function close(channelConfig, tradeNo) {
    const bizContent = {
        out_trade_no: tradeNo
    };
    
    const params = buildRequestParams(channelConfig, 'alipay.trade.close', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_close_response;
    if (result.code !== '10000' && result.code !== '40004') {
        throw new Error(result.sub_msg || result.msg || '关闭订单失败');
    }
    
    return { code: 0 };
}

/**
 * 查询订单
 */
async function query(channelConfig, tradeNo) {
    const bizContent = {
        out_trade_no: tradeNo
    };
    
    const params = buildRequestParams(channelConfig, 'alipay.trade.query', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_query_response;
    if (result.code !== '10000') {
        throw new Error(result.sub_msg || result.msg || '查询订单失败');
    }
    
    return {
        trade_no: result.out_trade_no,
        api_trade_no: result.trade_no,
        buyer: result.buyer_user_id || result.buyer_open_id,
        total_amount: result.total_amount,
        trade_status: result.trade_status
    };
}

/**
 * 构建支付表单HTML
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
 * 添加直付通参数
 */
function addDirectPayParams(bizContent, channelConfig) {
    if (channelConfig.appmchid) {
        bizContent.extend_params = {
            sys_service_provider_id: channelConfig.appmchid
        };
        bizContent.settle_info = {
            settle_period_time: '1d',
            settle_detail_infos: [{
                trans_in_type: 'defaultSettle',
                amount: bizContent.total_amount
            }]
        };
    }
    return bizContent;
}

/**
 * MAPI支付
 */
async function mapi(channelConfig, orderInfo, conf) {
    const { trade_no, device, mdevice, method } = orderInfo;
    const apptype = channelConfig.apptype || [];
    
    if (method === 'app') {
        return await apppay(channelConfig, orderInfo, conf);
    } else if (method === 'jsapi') {
        if (apptype.includes('7')) {
            return await jsapipay(channelConfig, orderInfo, conf);
        } else {
            return await jspay(channelConfig, orderInfo, conf);
        }
    } else if (mdevice === 'alipay' && apptype.includes('4') && !apptype.includes('2')) {
        return { type: 'jump', url: `/pay/jspay/${trade_no}/?d=1` };
    } else if (device === 'mobile' && (apptype.includes('3') || apptype.includes('4') || apptype.includes('8')) && !apptype.includes('2') || device === 'pc' && !apptype.includes('1')) {
        return await qrcode(channelConfig, orderInfo, conf);
    } else {
        return { type: 'jump', url: `/pay/submit/${trade_no}/` };
    }
}

/**
 * 电脑网站支付扫码
 */
async function qrcodepc(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, return_url, is_mobile, clientip } = orderInfo;
    const siteurl = conf.siteurl || '';
    
    if (is_mobile) {
        // 手机端获取二维码
        const config = {
            ...channelConfig,
            notify_url,
            return_url
        };
        
        const bizContent = {
            out_trade_no: trade_no,
            total_amount: money.toFixed(2),
            subject: name,
            qr_pay_mode: '4'
        };
        
        if (clientip) {
            bizContent.business_params = { mc_create_trade_ip: clientip };
        }
        
        addDirectPayParams(bizContent, channelConfig);
        
        const params = buildRequestParams(config, 'alipay.trade.precreate', bizContent, channelConfig);
        const response = await sendRequest(params);
        
        const result = response.alipay_trade_precreate_response;
        if (result.code !== '10000') {
            throw new Error(result.sub_msg || result.msg || '获取二维码失败');
        }
        
        return { type: 'qrcode', page: 'alipay_qrcode', url: result.qr_code };
    } else {
        return { type: 'qrcode', page: 'alipay_qrcodepc', url: `/pay/submitpc/${trade_no}/` };
    }
}

/**
 * 电脑网站支付扫码跳转
 */
async function submitpc(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, return_url, clientip } = orderInfo;
    
    const config = {
        ...channelConfig,
        notify_url,
        return_url
    };
    
    let bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name,
        qr_pay_mode: '4',
        qrcode_width: '230'
    };
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    addDirectPayParams(bizContent, channelConfig);
    
    const params = buildRequestParams(config, 'alipay.trade.page.pay', bizContent, channelConfig);
    const html = '<!DOCTYPE html><html><body><style>body{margin:0;padding:0}.waiting{position:absolute;width:100%;height:100%;background:#fff url(/assets/img/load.gif) no-repeat fixed center/80px;}</style><div class="waiting"></div>' + buildPayForm(params) + '</body></html>';
    
    return { type: 'html', data: html };
}

/**
 * 手机网站支付扫码跳转
 */
async function submitwap(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, return_url, clientip } = orderInfo;
    
    const config = {
        ...channelConfig,
        notify_url,
        return_url
    };
    
    let bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name
    };
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    addDirectPayParams(bizContent, channelConfig);
    
    const params = buildRequestParams(config, 'alipay.trade.wap.pay', bizContent, channelConfig);
    
    return { type: 'html', data: buildPayForm(params) };
}

/**
 * APP支付
 */
async function apppay(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, method, clientip } = orderInfo;
    
    const config = {
        ...channelConfig,
        notify_url
    };
    
    let bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name,
        product_code: 'QUICK_MSECURITY_PAY'
    };
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    addDirectPayParams(bizContent, channelConfig);
    
    const params = buildRequestParams(config, 'alipay.trade.app.pay', bizContent, channelConfig);
    
    // 构建SDK参数字符串
    const sdkParams = Object.keys(params).sort().map(k => `${k}=${encodeURIComponent(params[k])}`).join('&');
    
    if (method === 'app') {
        return { type: 'app', data: sdkParams };
    }
    
    const code_url = `alipays://platformapi/startApp?appId=20000125&orderSuffix=${encodeURIComponent(sdkParams)}`;
    return {
        type: 'page',
        page: 'alipay_h5',
        data: { code_url, redirect_url: `/pay/ok/${trade_no}/` }
    };
}

/**
 * 预授权支付
 */
async function preauth(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, clientip } = orderInfo;
    
    const config = {
        ...channelConfig,
        notify_url: notify_url.replace('/notify/', '/preauthnotify/')
    };
    
    let bizContent = {
        out_order_no: trade_no,
        out_request_no: trade_no,
        order_title: name,
        amount: money.toFixed(2),
        product_code: 'PREAUTH_PAY'
    };
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    addDirectPayParams(bizContent, channelConfig);
    
    const params = buildRequestParams(config, 'alipay.fund.auth.order.app.freeze', bizContent, channelConfig);
    
    // 构建SDK参数字符串
    const sdkParams = Object.keys(params).sort().map(k => `${k}=${encodeURIComponent(params[k])}`).join('&');
    
    const code_url = `alipays://platformapi/startApp?appId=20000125&orderSuffix=${encodeURIComponent(sdkParams)}`;
    return {
        type: 'page',
        page: 'alipay_h5',
        data: { code_url, redirect_url: `/pay/ok/${trade_no}/` }
    };
}

/**
 * 当面付JS支付
 */
async function jspay(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, method, openid, clientip } = orderInfo;
    
    if (!openid) {
        return { type: 'error', msg: '需要获取用户openid' };
    }
    
    const config = {
        ...channelConfig,
        notify_url
    };
    
    const user_type = openid.startsWith('2088') ? 'userid' : 'openid';
    
    let bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name
    };
    
    if (user_type === 'userid') {
        bizContent.buyer_id = openid;
    } else {
        bizContent.buyer_open_id = openid;
    }
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    addDirectPayParams(bizContent, channelConfig);
    
    const params = buildRequestParams(config, 'alipay.trade.create', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_create_response;
    if (result.code !== '10000') {
        throw new Error(result.sub_msg || result.msg || '下单失败');
    }
    
    const alipay_trade_no = result.trade_no;
    
    if (method === 'jsapi') {
        return { type: 'jsapi', data: alipay_trade_no };
    }
    
    return {
        type: 'page',
        page: 'alipay_jspay',
        data: { alipay_trade_no, redirect_url: `/pay/ok/${trade_no}/` }
    };
}

/**
 * JSAPI支付
 */
async function jsapipay(channelConfig, orderInfo, conf) {
    const { trade_no, money, name, notify_url, openid, sub_appid, clientip } = orderInfo;
    
    if (!openid) {
        return { type: 'error', msg: '需要获取用户openid' };
    }
    
    const user_type = openid.startsWith('2088') ? 'userid' : 'openid';
    
    const config = {
        ...channelConfig,
        notify_url
    };
    
    let bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name,
        product_code: 'JSAPI_PAY',
        op_app_id: sub_appid || channelConfig.appid
    };
    
    if (user_type === 'openid') {
        bizContent.buyer_open_id = openid;
    } else {
        bizContent.buyer_id = openid;
    }
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    addDirectPayParams(bizContent, channelConfig);
    
    const params = buildRequestParams(config, 'alipay.trade.create', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_create_response;
    if (result.code !== '10000') {
        throw new Error(result.sub_msg || result.msg || '下单失败');
    }
    
    return { type: 'jsapi', data: result.trade_no };
}

/**
 * 支付宝小程序支付
 */
async function alipaymini(channelConfig, orderInfo, conf, authCode) {
    const { trade_no, money, name, notify_url, clientip } = orderInfo;
    
    if (!authCode) {
        return { code: -1, msg: 'auth_code不能为空' };
    }
    
    // 通过auth_code换取用户信息
    const oauthResult = await alipayOAuthByCode(channelConfig, authCode);
    if (!oauthResult.success) {
        return { code: -1, msg: oauthResult.msg || '获取用户信息失败' };
    }
    
    const { user_id, user_type, app_id } = oauthResult;
    
    const config = {
        ...channelConfig,
        notify_url
    };
    
    let bizContent = {
        out_trade_no: trade_no,
        total_amount: money.toFixed(2),
        subject: name,
        product_code: 'JSAPI_PAY',
        op_app_id: app_id || channelConfig.appid
    };
    
    if (user_type === 'openid') {
        bizContent.buyer_open_id = user_id;
    } else {
        bizContent.buyer_id = user_id;
    }
    
    if (clientip) {
        bizContent.business_params = { mc_create_trade_ip: clientip };
    }
    
    addDirectPayParams(bizContent, channelConfig);
    
    const params = buildRequestParams(config, 'alipay.trade.create', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_create_response;
    if (result.code !== '10000') {
        return { code: -1, msg: result.sub_msg || result.msg || '支付宝下单失败' };
    }
    
    return { code: 0, data: result.trade_no };
}

/**
 * H5跳转小程序支付
 */
async function minipay(channelConfig, orderInfo, conf) {
    const { trade_no } = orderInfo;
    const appId = channelConfig.appid;
    
    const code_url = `alipays://platformapi/startapp?appId=${appId}&page=pages/pay/pay&query=${encodeURIComponent(`trade_no=${trade_no}`)}`;
    
    return {
        type: 'page',
        page: 'alipay_h5',
        data: { code_url, redirect_url: `/pay/ok/${trade_no}/` }
    };
}

/**
 * 支付成功页面
 */
function ok() {
    return { type: 'page', page: 'ok' };
}

/**
 * 同步回调
 */
async function returnCallback(channelConfig, getData, order) {
    try {
        const sign = getData.sign;
        const signType = getData.sign_type || 'RSA2';
        
        const params = { ...getData };
        delete params.sign;
        delete params.sign_type;
        
        const signString = buildSignString(params);
        
        let publicKey = channelConfig.appkey;
        const alipayCertPath = getCertAbsolutePath(channelConfig, 'alipayCert');
        if (alipayCertPath && fs.existsSync(alipayCertPath)) {
            const certPublicKey = getPublicKeyFromCert(alipayCertPath);
            if (certPublicKey) publicKey = certPublicKey;
        }
        
        if (!publicKey) {
            return { success: false, msg: '支付宝公钥未配置' };
        }
        
        const isValid = rsaVerify(signString, sign, publicKey, signType);
        
        if (!isValid) {
            return { success: false, msg: '支付宝返回验证失败' };
        }
        
        if (getData.out_trade_no !== order.trade_no) {
            return { success: false, msg: '订单号不匹配' };
        }
        
        if (Math.abs(parseFloat(getData.total_amount) - parseFloat(order.real_money)) > 0.01) {
            return { success: false, msg: '订单金额不匹配' };
        }
        
        return {
            success: true,
            api_trade_no: getData.trade_no
        };
    } catch (error) {
        console.error('支付宝同步回调处理错误:', error);
        return { success: false, msg: error.message };
    }
}

/**
 * 预授权支付回调
 */
async function preauthnotify(channelConfig, notifyData, order, conf, ordername) {
    try {
        const sign = notifyData.sign;
        const signType = notifyData.sign_type || 'RSA2';
        
        const params = { ...notifyData };
        delete params.sign;
        delete params.sign_type;
        
        const signString = buildSignString(params);
        
        let publicKey = channelConfig.appkey;
        const alipayCertPath = getCertAbsolutePath(channelConfig, 'alipayCert');
        if (alipayCertPath && fs.existsSync(alipayCertPath)) {
            const certPublicKey = getPublicKeyFromCert(alipayCertPath);
            if (certPublicKey) publicKey = certPublicKey;
        }
        
        if (!publicKey) {
            return { success: false };
        }
        
        const isValid = rsaVerify(signString, sign, publicKey, signType);
        
        if (!isValid) {
            return { success: false };
        }
        
        if (notifyData.out_order_no !== order.trade_no) {
            return { success: false };
        }
        
        const authNo = notifyData.auth_no;
        const buyerId = notifyData.payer_user_id;
        
        // 资金授权转交易
        const config = {
            ...channelConfig,
            notify_url: conf.localurl + 'pay/notify/' + order.trade_no + '/'
        };
        
        let bizContent = {
            out_trade_no: order.trade_no,
            total_amount: order.real_money,
            subject: ordername,
            product_code: 'PREAUTH_PAY',
            auth_no: authNo,
            auth_confirm_mode: 'COMPLETE'
        };
        
        const tradeParams = buildRequestParams(config, 'alipay.trade.pay', bizContent, channelConfig);
        const response = await sendRequest(tradeParams);
        
        const result = response.alipay_trade_pay_response;
        if (result.code !== '10000') {
            return {
                success: true,
                api_trade_no: authNo,
                buyer: buyerId,
                status: 4
            };
        }
        
        return {
            success: true,
            api_trade_no: result.trade_no,
            buyer: result.buyer_user_id,
            total_amount: result.total_amount
        };
    } catch (error) {
        console.error('预授权回调处理错误:', error);
        return { success: false };
    }
}

/**
 * 结算确认
 */
async function settleConfirm(channelConfig, tradeNo, amount, freeze = false) {
    const bizContent = {
        trade_no: tradeNo,
        settle_info: {
            settle_detail_infos: [{
                trans_in_type: freeze ? 'freezeSettle' : 'defaultSettle',
                amount: amount
            }]
        }
    };
    
    const params = buildRequestParams(channelConfig, 'alipay.trade.settle.confirm', bizContent, channelConfig);
    const response = await sendRequest(params);
    
    const result = response.alipay_trade_settle_confirm_response;
    if (result.code !== '10000') {
        throw new Error(result.sub_msg || result.msg || '结算确认失败');
    }
    
    return { code: 0, trade_no: result.trade_no };
}

/**
 * 支付宝应用网关
 */
async function appgw(channelConfig, notifyData) {
    const sign = notifyData.sign;
    const signType = notifyData.sign_type || 'RSA2';
    
    const params = { ...notifyData };
    delete params.sign;
    delete params.sign_type;
    
    const signString = buildSignString(params);
    
    let publicKey = channelConfig.appkey;
    const alipayCertPath = getCertAbsolutePath(channelConfig, 'alipayCert');
    if (alipayCertPath && fs.existsSync(alipayCertPath)) {
        const certPublicKey = getPublicKeyFromCert(alipayCertPath);
        if (certPublicKey) publicKey = certPublicKey;
    }
    
    if (!publicKey) {
        return { success: false, msg: 'check sign fail' };
    }
    
    const isValid = rsaVerify(signString, sign, publicKey, signType);
    
    if (!isValid) {
        return { success: false, msg: 'check sign fail' };
    }
    
    const msgMethod = notifyData.msg_method;
    let bizContent = {};
    
    if (notifyData.biz_content) {
        try {
            bizContent = JSON.parse(notifyData.biz_content);
        } catch (e) { }
    }
    
    // 根据消息类型处理
    if (msgMethod === 'alipay.merchant.tradecomplain.changed') {
        return { success: true, type: 'tradecomplain', data: bizContent };
    } else if (msgMethod === 'ant.merchant.expand.indirect.zft.passed') {
        return { success: true, type: 'zft_passed', data: bizContent };
    } else if (msgMethod === 'ant.merchant.expand.indirect.zft.rejected') {
        return { success: true, type: 'zft_rejected', data: bizContent };
    }
    
    return { success: true };
}

/**
 * 通过auth_code换取用户信息
 */
async function alipayOAuthByCode(channelConfig, authCode) {
    const params = {
        app_id: channelConfig.appid,
        method: 'alipay.system.oauth.token',
        format: 'JSON',
        charset: 'utf-8',
        sign_type: 'RSA2',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        version: '1.0',
        grant_type: 'authorization_code',
        code: authCode
    };
    
    // 添加证书信息
    const appCertPath = getCertAbsolutePath(channelConfig, 'appCert');
    const rootCertPath = getCertAbsolutePath(channelConfig, 'alipayRootCert');
    if (appCertPath && rootCertPath && fs.existsSync(appCertPath) && fs.existsSync(rootCertPath)) {
        const appCertSN = getCertSN(appCertPath);
        const alipayRootCertSN = getRootCertSN(rootCertPath);
        if (appCertSN) params.app_cert_sn = appCertSN;
        if (alipayRootCertSN) params.alipay_root_cert_sn = alipayRootCertSN;
    }
    
    const signString = buildSignString(params);
    params.sign = rsaSign(signString, channelConfig.appsecret);
    
    try {
        const response = await sendRequest(params);
        const result = response.alipay_system_oauth_token_response;
        
        if (!result || result.code) {
            return { success: false, msg: result?.sub_msg || result?.msg || '获取用户信息失败' };
        }
        
        const userId = result.user_id || result.open_id;
        const userType = result.user_id ? 'userid' : 'openid';
        
        return {
            success: true,
            user_id: userId,
            user_type: userType,
            app_id: result.auth_app_id,
            access_token: result.access_token
        };
    } catch (e) {
        return { success: false, msg: e.message };
    }
}

/**
 * 生成OAuth跳转URL
 */
function getOAuthUrl(channelConfig, redirectUrl, scope = 'auth_base') {
    const appId = channelConfig.appid;
    const encodedRedirect = encodeURIComponent(redirectUrl);
    return `https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=${appId}&scope=${scope}&redirect_uri=${encodedRedirect}`;
}

/**
 * 辅助函数 - 延时
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 判断是否支持合单支付
 */
function isCombinePay(money, conf) {
    if (!conf.alicombine_open || !conf.wxcombine_minmoney) return false;
    if (money < parseFloat(conf.wxcombine_minmoney)) return false;
    return true;
}

/**
 * 构建合单支付参数
 */
function combineOrderParams(bizContent, channelConfig, conf) {
    let sub_mchid = channelConfig.appmchid;
    let sub_mchids = null;
    
    if (channelConfig.appmchid && channelConfig.appmchid.includes(',')) {
        sub_mchids = channelConfig.appmchid.split(',');
        // 随机打乱
        sub_mchids = sub_mchids.sort(() => Math.random() - 0.5);
    }
    
    let money = Math.round(parseFloat(bizContent.total_amount) * 100);
    let subnum = sub_mchids ? sub_mchids.length : 2;
    if (subnum > 6) subnum = 6;
    let submoney = Math.floor(money / subnum);
    
    if (subnum < 6 && conf.wxcombine_submoney) {
        while (submoney > Math.floor(parseFloat(conf.wxcombine_submoney) * 100)) {
            subnum++;
            submoney = Math.floor(money / subnum);
            if (subnum === 6) break;
        }
    }
    
    const submoneys = [];
    for (let i = 0; i < subnum; i++) {
        submoneys.push(submoney);
    }
    const mod = money % subnum;
    if (mod > 0) {
        for (let i = 0; i < mod; i++) {
            submoneys[i] += 1;
        }
    }
    
    const order_details = [];
    const sub_orders = [];
    let i = 1;
    
    for (const subMoney of submoneys) {
        const order_detail = {
            app_id: channelConfig.appid,
            out_trade_no: bizContent.out_trade_no + i,
            product_code: bizContent.product_code,
            total_amount: (subMoney / 100).toFixed(2),
            subject: bizContent.subject,
            business_params: bizContent.business_params,
            sub_merchant: { 
                merchant_id: sub_mchids ? sub_mchids[(i - 1) % sub_mchids.length] : sub_mchid 
            },
            settle_info: {
                settle_period_time: '1d',
                settle_detail_infos: [{
                    trans_in_type: 'defaultSettle',
                    amount: (subMoney / 100).toFixed(2)
                }]
            }
        };
        
        if (bizContent.op_app_id) order_detail.op_app_id = bizContent.op_app_id;
        if (bizContent.buyer_id) order_detail.buyer_id = bizContent.buyer_id;
        if (bizContent.buyer_open_id) order_detail.buyer_open_id = bizContent.buyer_open_id;
        
        order_details.push(order_detail);
        sub_orders.push({
            sub_trade_no: order_detail.out_trade_no,
            money: order_detail.total_amount
        });
        i++;
    }
    
    const combineBizContent = {
        out_merge_no: bizContent.out_trade_no,
        order_details: order_details
    };
    
    return { bizContent: combineBizContent, sub_orders };
}

/**
 * 合单支付退款
 */
async function refundCombine(channelConfig, order, subOrders) {
    if (!subOrders || subOrders.length === 0) {
        return { code: -1, msg: '子订单数据不存在' };
    }
    
    let refundmoney = parseFloat(order.refundmoney);
    
    for (const sub_order of subOrders) {
        if (sub_order.status === 2 && (!sub_order.refundmoney || sub_order.refundmoney >= sub_order.money)) {
            continue;
        }
        
        let money = parseFloat(sub_order.money);
        if (sub_order.status === 2) {
            money = Math.round((parseFloat(sub_order.money) - parseFloat(sub_order.refundmoney || 0)) * 100) / 100;
        }
        
        if (money > refundmoney) {
            money = refundmoney;
        }
        
        const refund_no = Date.now().toString() + Math.floor(Math.random() * 100000);
        const bizContent = {
            trade_no: sub_order.api_trade_no,
            refund_amount: money.toFixed(2),
            out_request_no: refund_no
        };
        
        try {
            const params = buildRequestParams(channelConfig, 'alipay.trade.refund', bizContent, channelConfig);
            const response = await sendRequest(params);
            const result = response.alipay_trade_refund_response;
            
            if (!result || result.code !== '10000') {
                return { code: -1, msg: result?.sub_msg || result?.msg || '退款失败' };
            }
        } catch (error) {
            return { code: -1, msg: error.message };
        }
        
        refundmoney = Math.round((refundmoney - money) * 100) / 100;
        if (refundmoney <= 0) break;
    }
    
    return { code: 0 };
}

/**
 * 合单支付关闭订单
 */
async function closeCombine(channelConfig, order, subOrders) {
    if (!subOrders || subOrders.length === 0) {
        return { code: -1, msg: '子订单数据不存在' };
    }
    
    for (const sub_order of subOrders) {
        const bizContent = {
            out_trade_no: sub_order.sub_trade_no
        };
        
        try {
            const params = buildRequestParams(channelConfig, 'alipay.trade.close', bizContent, channelConfig);
            const response = await sendRequest(params);
            const result = response.alipay_trade_close_response;
            
            if (!result || result.code !== '10000') {
                // 如果订单已关闭或不存在，继续处理下一个
                if (result?.sub_code === 'ACQ.TRADE_NOT_EXIST' || result?.sub_code === 'ACQ.TRADE_HAS_CLOSE') {
                    continue;
                }
                return { code: -1, msg: result?.sub_msg || result?.msg || '关闭订单失败' };
            }
        } catch (error) {
            return { code: -1, msg: error.message };
        }
    }
    
    return { code: 0 };
}

/**
 * 合单支付异步通知处理
 */
async function combineNotify(channelConfig, notifyData, order, conf) {
    const out_trade_no = notifyData.out_merge_no;
    const buyer_id = notifyData.buyer_id || '';
    const order_detail_results = typeof notifyData.order_detail_results === 'string'
        ? JSON.parse(notifyData.order_detail_results)
        : notifyData.order_detail_results;
    
    if (notifyData.merge_pay_status === 'FINISHED' && out_trade_no === order.trade_no) {
        const sub_orders = order_detail_results.map(detail => ({
            sub_trade_no: detail.out_trade_no,
            api_trade_no: detail.trade_no,
            money: detail.total_amount
        }));
        
        // 返回合单支付的结果
        return {
            success: true,
            api_trade_no: out_trade_no,
            buyer: buyer_id,
            combine: true,
            sub_orders: sub_orders,
            order_detail_results: order_detail_results
        };
    }
    
    return { success: false };
}

/**
 * 合单支付同步回调
 */
async function combineReturn(channelConfig, params, order) {
    return { type: 'page', page: 'return' };
}

module.exports = {
    info,
    submit,
    mapi,
    qrcode,
    qrcodepc,
    submitpc,
    submitwap,
    apppay,
    preauth,
    jspay,
    jsapipay,
    alipaymini,
    minipay,
    ok,
    notify,
    return: returnCallback,
    preauthnotify,
    refund,
    close,
    appgw
};
