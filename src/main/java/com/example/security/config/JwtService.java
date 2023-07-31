package com.example.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "aa5d0a646ced270e4c625fc3f5362a577242402ceb238ef3a5025ac22cb27aa1eb170ac4f2c2dd3b804c5155b8b575506efc51621924f89b27d32f595e907925";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);// Method reference
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims); // Trả về kiểu T
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())//khóa bí mật
                .build()
                .parseClaimsJws(token) // pars tất cả các claims thành 1 claims duy nhất
                .getBody();// trả về Claims sau khi parseClaimsJwt (pars token)
    }

    public String generateToken(UserDetails userDetails){
        return  generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userName = extractUsername(token);
        return (userName.equals(userDetails.getUsername()))&& !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes); // Creates a new SecretKey instance for use with HMAC-SHA algorithms based on the specified key byte array
    }


    /*Subject: Tên người dùng hoặc ID của người dùng.
    Issuer: Tên của tổ chức hoặc ứng dụng đã tạo token.
    Audience: Tên của tổ chức hoặc ứng dụng mà token được dành cho.
    Issued at: Thời gian mà token được tạo.
    Expiration time: Thời gian mà token hết hạn.*/
}
