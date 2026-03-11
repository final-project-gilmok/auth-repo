package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.common.dto.AuthUserDto;
import kr.gilmok.common.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("사용자 조회 실패 - 존재하지 않는 사용자");
                    return new UsernameNotFoundException("존재하지 않는 사용자입니다.");
                });

        AuthUserDto authUserDto = new AuthUserDto(
                user.getId(),
                user.getUsername(),
                user.getPasswordHash(),
                user.getRole(),
                user.getStatus().name()
        );

        log.debug("사용자 인증 정보 로드 성공 - userId: {}", user.getId());
        return new CustomUserDetails(authUserDto);
    }
}
