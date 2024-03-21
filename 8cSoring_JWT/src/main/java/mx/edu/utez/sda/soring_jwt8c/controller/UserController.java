package mx.edu.utez.sda.soring_jwt8c.controller;

import mx.edu.utez.sda.soring_jwt8c.entity.AuthRequest;
import mx.edu.utez.sda.soring_jwt8c.entity.UserInfo;
import mx.edu.utez.sda.soring_jwt8c.service.JwtService;
import mx.edu.utez.sda.soring_jwt8c.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    private UserInfoService service;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/index")
    public String index(){
        return "Servicio Index";
    }

    @PostMapping("/registrame")
    public String registrame(@RequestBody UserInfo userInfo){
        return service.guardarUser(userInfo);
    }

    @GetMapping("/admin/test")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String paraAdmin() {
        return "Este endpoint es solo para admin :v";
    }

    @GetMapping("/user/test")
    @PreAuthorize("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")
    public String paraUser() {
        return "Este endpoint es solo para usarios y admins :v";
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest authRequest){
        try{
            Authentication authentication =
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    authRequest.getUsername(),
                                    authRequest.getPassword())
                    );
            if(authentication.isAuthenticated()){
                return jwtService.generateToken(authRequest.getUsername());
            } else {
                System.out.println("No autenticado en el login");
                throw new UsernameNotFoundException("Usuario Invalido");
            }
        }catch (Exception e){
            System.out.println("No autenticado en el catch");
            throw new UsernameNotFoundException("Usuario Invalido");
        }
    }
}
