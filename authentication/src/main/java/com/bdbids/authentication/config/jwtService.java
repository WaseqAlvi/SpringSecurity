package com.bdbids.authentication.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service

public class jwtService {
    private static final String SecretKey="4ada77a9573a1ff937e34403fe282cab2c2a2f7fab86a2d9dc2411e82490f9ce";
    public String extractUserName(String token) {
        return extractClaim(token,Claims::getSubject);
    }
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts.builder().
                setClaims(extraClaims).
                setSubject(userDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000+60*24))
                .signWith(getSingingKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }


    public Claims extractAllClaims(String token){

        return Jwts.parserBuilder().setSigningKey(getSingingKey()).build().parseClaimsJws(token)
                .getBody();
    }


    private Key getSingingKey(){
        byte [] keyBytes= Decoders.BASE64.decode(SecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public <T> T extractClaim (String token, Function<Claims,T> claimsResolver){
        final Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public boolean isTokenValid(String token, UserDetails userDetails){
    final String username=extractUserName(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }
    private Date extractExpiration (String token){
        return extractClaim(token,Claims::getExpiration);
    }

}
