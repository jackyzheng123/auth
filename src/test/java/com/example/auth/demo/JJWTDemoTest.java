package com.example.auth.demo;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

/**
 * JJWT
 * 它是为了更友好在JVM上使用JWT，是基本于JWT, JWS, JWE, JWK框架的java实现。
 *
 *
 * @Description
 * @Author Carson Cheng
 * @Date 2019/11/26 15:16
 * @Version V1.0
 **/
public class JJWTDemoTest {

    private static final String SECRET = "DyoonSecret_0581";

    /**
     * 获取token
     */
    private static String getJwtToken(){
        Date iatDate = new Date();
        // expire time
        Calendar nowTime = Calendar.getInstance();
        //有10天有效期
        nowTime.add(Calendar.DATE, 10);
        Date expiresDate = nowTime.getTime();
        Claims claims = Jwts.claims();
        claims.put("name","cy");
        claims.put("userId", "222");
        claims.setAudience("cy");
        claims.setIssuer("cy");
        String token = Jwts.builder()
                .setClaims(claims)
                .setExpiration(expiresDate)
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        return token;
    }

    /**
     * 解析token
     * @param token
     */
    public static void parseJwtToken(String token) {
        try{
            Jws<Claims> jws = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);

            String signature = jws.getSignature();
            System.out.println("签名：" + signature);

            Map<String, String> header = jws.getHeader();
            header.forEach((k, v) ->{
                System.out.println("header:" + k + "=" + v);
            });

            Claims claims = jws.getBody();
            System.out.println("claims: " + claims.toString());

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void main (String[] args){
        String token = getJwtToken();
        System.out.println("生成token： " + token);
        parseJwtToken(token);
    }
}
