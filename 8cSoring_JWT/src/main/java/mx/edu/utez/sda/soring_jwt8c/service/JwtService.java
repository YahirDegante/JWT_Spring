package mx.edu.utez.sda.soring_jwt8c.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {
    private static final String SECRET = "CADENA-DE-FIRMADO";

    private Key getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Claims extracAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        final Claims claims = extracAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String createToken(Map<String, Object> claims, String userName){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateToken(String userName){
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName);
    }

    public String extractUserName( String token){
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    public Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails){
        final String username = extractUserName(token);
        return (
                username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
