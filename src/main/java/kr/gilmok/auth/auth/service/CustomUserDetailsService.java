package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.UserErrorCode;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.common.dto.AuthUserDto;
import kr.gilmok.common.exception.CustomException;
import kr.gilmok.common.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomException(UserErrorCode.USER_NOT_FOUND));

        AuthUserDto authUserDto = new AuthUserDto(
                user.getId(),
                user.getUsername(),
                user.getPasswordHash(),
                user.getRole(),
                user.getStatus().name()
        );

        return new CustomUserDetails(authUserDto);
    }
}
