package kr.gilmok.auth.auth.service;

import kr.gilmok.auth.auth.dto.SignupRequest;
import kr.gilmok.auth.auth.entity.User;
import kr.gilmok.auth.auth.exception.UserErrorCode;
import kr.gilmok.auth.auth.repository.UserRepository;
import kr.gilmok.common.exception.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void signup(SignupRequest request) {
        validatePasswordMatch(request.password(), request.passwordConfirm());
        validateDuplicateUsername(request.username());

        String encodedPassword = passwordEncoder.encode(request.password());
        User user = User.createNewUser(request.username(), encodedPassword);

        userRepository.save(user);
    }

    private void validatePasswordMatch(String password, String passwordConfirm) {
        if (!password.equals(passwordConfirm)) {
            throw new CustomException(UserErrorCode.PASSWORD_MISMATCH);
        }
    }

    private void validateDuplicateUsername(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            throw new CustomException(UserErrorCode.DUPLICATE_USERNAME);
        });
    }
}