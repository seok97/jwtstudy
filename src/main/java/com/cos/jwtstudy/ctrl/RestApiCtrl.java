package com.cos.jwtstudy.ctrl;

import com.cos.jwtstudy.model.User;
import com.cos.jwtstudy.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

// @CrossOrigin 이 이노테이션을 사용하여 cors설정을 해제 할 수 있어 security config 설정에 필터를 설정하지 않아도 되지만
// 인증이 필요하지 않은 경우에만 적용 되기 때문에 로그인이 필요한 요청은 적용되지 않는다.
@RestController
public class RestApiCtrl {

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    UserRepository userRepository;

    @GetMapping("home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }
}
