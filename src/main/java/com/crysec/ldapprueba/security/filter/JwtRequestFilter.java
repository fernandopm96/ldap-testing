package com.crysec.ldapprueba.security.filter;

import com.crysec.ldapprueba.models.User;
import com.crysec.ldapprueba.security.utils.JwtTokenUtil;
import com.crysec.ldapprueba.services.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        final String requestTokenHeader = request.getHeader("authorization");

        String username = null;
        String jwtToken = null;
        jwtUserDetailsService = new JwtUserDetailsService();

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        if(requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")){
            jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch(IllegalArgumentException e){
                System.out.println("Unable to get JWT Token.");
            } catch(ExpiredJwtException e2){
                System.out.println("JWT Token has expired.");
            }
        } else {
            System.out.println("JWT Token does not starts with Bearer String.");
        }
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            User userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
            if(jwtTokenUtil.validateToken(jwtToken, userDetails)){
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, grantedAuthorities);
                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }

        }
        filterChain.doFilter(request, response);

    }
}
