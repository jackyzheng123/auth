package com.example.auth.demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.util.StringUtils;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * https://blog.csdn.net/achenyuan/article/details/80829401#jwt%E5%85%A8%E9%9D%A2%E8%A7%A3%E8%AF%BB
 *
 *  JWT消息构成
 * 一个token分3部分，按顺序为
 *
 * 头部（header) ： 头信息指定了该JWT使用的签名算法：header = '{"alg":"HS256","typ":"JWT"}'
 * 载荷（payload)： 消息体包含了JWT的意图
 * 签名（signature) ：
 *                  key = 'secretkey'
 *                  unsignedToken = encodeBase64(header) + '.' + encodeBase64(payload)
 *                  signature = HMAC-SHA256(key, unsignedToken)
 * 由三部分生成token
 * 3部分之间用“.”号做分隔。
 * token = encodeBase64(header) + '.' + encodeBase64(payload) + '.' + encodeBase64(signature)
 *
 * 如：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
 * 验证token地址：https://jwt.io/
 *
 * 客户端通常将JWT通过HTTP的Authorization header发送给服务端，服务端使用自己保存的key计算、验证签名以判断该JWT是否可信：
 * Authorization: Bearer eyJhbGci*...<snip>...*yu5CSpyHI
 *
 *
 * 头部（header)
 * Jwt的头部承载两部分信息：
 * 声明类型，这里是jwt
 * 声明加密的算法 通常直接使用 HMAC SHA256
 *
 * JWT里验证和签名使用的算法，可选择下面的。
 * JWS	    算法名称	    描述
 * HS256	HMAC256	    HMAC with SHA-256
 * HS384	HMAC384	    HMAC with SHA-384
 * HS512	HMAC512	    HMAC with SHA-512
 * RS256	RSA256	    RSASSA-PKCS1-v1_5 with SHA-256
 * RS384	RSA384	    RSASSA-PKCS1-v1_5 with SHA-384
 * RS512	RSA512	    RSASSA-PKCS1-v1_5 with SHA-512
 * ES256	ECDSA256	ECDSA with curve P-256 and SHA-256
 * ES384	ECDSA384	ECDSA with curve P-384 and SHA-384
 * ES512	ECDSA512	ECDSA with curve P-521 and SHA-512
 *
 * 载荷（payload)
 * 载荷就是存放有效信息的地方。基本上填2种类型数据
 * -标准中注册的声明的数据
 * -自定义数据
 * 由这2部分内部做base64加密。最张数据进入JWT的chaims里存放。
 *
 * iss: jwt签发者
 * sub: jwt所面向的用户
 * aud: 接收jwt的一方
 * exp: jwt的过期时间，这个过期时间必须要大于签发时间
 * nbf: 定义在什么时间之前，该jwt都是不可用的.
 * iat: jwt的签发时间
 * jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
 *
 * 签名signature
 * jwt的第三部分是一个签证信息，这个签证信息算法如下：
 * base64UrlEncode(header) + "." + base64UrlEncode(payload) + your-256-bit-secret
 * 这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串，然后通过header中声明的加密方式进行加盐secret组合加密，然后就构成了jwt的第三部分。
 *
 *  基本上至此，JWT的API相关知识已经学完了，但是API不够有好，不停的用withClaim放数据。不够友好。下面推荐一款框架，相当于对JWT的实现框架
 *
 * @Description
 * @Author Carson Cheng
 * @Date 2019/11/26 14:56
 * @Version V1.0
 **/
public class JwtDemoTest {

    /**
     * APP登录Token的生成和解析
     *
     */

    /** token秘钥，请勿泄露，请勿随便修改 backups:JKKLJOoasdlfj */
    public static final String SECRET = "JKKLJOoasdlfj";
    /** token 过期时间: 10天 */
    public static final int calendarField = Calendar.DATE;
    public static final int calendarInterval = 10;

    /**
     * JWT生成Token.<br/>
     *
     * JWT构成: header, payload, signature
     *
     * @param user_id
     *            登录成功后用户user_id, 参数user_id不可传空
     */
    public static String createToken(Long user_id) {
        Date iatDate = new Date();
        // expire time
        Calendar nowTime = Calendar.getInstance();
        nowTime.add(calendarField, calendarInterval);
        Date expiresDate = nowTime.getTime();

        // header Map
        Map<String, Object> map = new HashMap<>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        // build token
        // param backups {iss:Service, aud:APP}
        String token = JWT.create().withHeader(map) // header
                .withClaim("iss", "Service") // payload
                .withClaim("aud", "APP")
                .withClaim("user_id", null == user_id ? null : user_id.toString())
                .withIssuedAt(iatDate) // sign time
                .withExpiresAt(expiresDate) // expire time
                .sign(Algorithm.HMAC256(SECRET)); // signature

        return token;
    }

    /**
     * 解密Token
     *
     * @param token
     * @return
     * @throws Exception
     */
    public static Map<String, Claim> verifyToken(String token) {
        DecodedJWT jwt = null;
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
            jwt = verifier.verify(token);
        } catch (Exception e) {
            // e.printStackTrace();
            // token 校验失败, 抛出Token验证非法异常
        }
        return jwt.getClaims();
    }

    /**
     * 根据Token获取user_id
     *
     * @param token
     * @return user_id
     */
    public static Long getAppUID(String token) {
        Map<String, Claim> claims = verifyToken(token);
        Claim user_id_claim = claims.get("user_id");
        if (null == user_id_claim || StringUtils.isEmpty(user_id_claim.asString())) {
            // token 校验失败, 抛出Token验证非法异常
        }
        return Long.valueOf(user_id_claim.asString());
    }


    public static void main (String[] args){
        // 生成token
        String token = createToken(100l);
        // 根据token获取用户id
        Long userId = getAppUID(token);
        System.out.println("生成token: " + token);
        System.out.println("根据token获取用户id : " + userId);

        // 解密Token
        Map<String, Claim> stringClaimMap = verifyToken(token);
        stringClaimMap.forEach((k, v) ->{
            System.out.println(k + "=" + v.asString());
        });
    }
}
