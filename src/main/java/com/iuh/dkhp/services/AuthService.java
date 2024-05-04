package com.iuh.dkhp.services;

import com.iuh.dkhp.dtos.responses.ManagementReponseDTO;
import com.iuh.dkhp.entities.Management;
import com.iuh.dkhp.entities.Routes;
import com.iuh.dkhp.utils.Bcrypt;
import com.nimbusds.jose.JOSEException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.text.ParseException;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    @Autowired
    private JWTServices jwtServices;
    private Bcrypt bcrypt = new Bcrypt();
    private final WebClient webClient;

    @Transactional
    public ResponseEntity<?> authenticationToken(String token) throws ParseException, JOSEException {
        String username = jwtServices.verifyToken(token);
        if (username != null) {
            if (username.contains("admin")) {
                Management managementFound = webClient.get()
                        .uri(Routes.OTHER.getValue()+"/managements/find-by-username/"+username)
                        .retrieve()
                        .bodyToMono(Management.class).block();
                return ResponseEntity.ok(managementFound);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Expired");
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Expired");
    }

    public ResponseEntity<Object> signInWithAdmin(String username, String password) throws Exception {
        Management managementFound = webClient.get()
                .uri(Routes.OTHER.getValue()+"/managements/find-by-username/"+username)
                .retrieve()
                .bodyToMono(Management.class).block();
        if (managementFound != null) {
            boolean matchPassword = bcrypt.comparePassword(managementFound.getPassword(), password);
            if (matchPassword == true) {

                // generate Access Token
                String accessToken = jwtServices.generateToken(managementFound.getUsername());

                // Hidden Password Of Student
                managementFound.setPassword(null);

                ManagementReponseDTO studentDTOResponse = new ManagementReponseDTO(managementFound, accessToken);
                return ResponseEntity.ok(studentDTOResponse);
            }
            else
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Don't match password");
        }
        else
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Don't Found Management");
    }
}
