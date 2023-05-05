package com.Mohamed.jwtAauthentification.services;

import com.Mohamed.jwtAauthentification.modals.Roles;
import com.Mohamed.jwtAauthentification.modals.Users;
import com.Mohamed.jwtAauthentification.repositorys.RolesRepository;
import com.Mohamed.jwtAauthentification.repositorys.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;

@Service
public class UserService {

    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private UserRepository userRepository;
    private RolesRepository rolesRepository;

    @Autowired
    public UserService(BCryptPasswordEncoder bCryptPasswordEncoder,
                       UserRepository userRepository,
                       RolesRepository rolesRepository){
        this.userRepository = userRepository;
        this.rolesRepository = rolesRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public Users findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public void saveUser(Users user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setActive(0);
        Roles userRole = rolesRepository.findByRoleName("USER");
        user.setRoleSet(new HashSet<Roles>(Arrays.asList(userRole)));
        userRepository.save(user);
    }

}
